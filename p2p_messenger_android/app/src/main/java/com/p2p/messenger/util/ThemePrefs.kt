package com.p2p.messenger.util

import android.app.Activity
import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.view.View
import android.widget.ImageView
import com.google.android.material.color.DynamicColors
import com.google.android.material.color.DynamicColorsOptions
import com.google.android.material.color.MaterialColors
import com.p2p.messenger.R
import com.google.android.material.R.color as MR
import java.io.File

/**
 * Görünüm tercihleri — spec dışı, salt kullanıcı deneyimi tercihi.
 */
object ThemePrefs {
    private const val PREFS_NAME = "p2p_settings"
    private const val KEY_TEXT_SCALE = "text_scale"
    private const val KEY_UI_SCALE = "ui_scale"
    private const val KEY_FONT_FAMILY = "font_family"
    private const val KEY_BG_COLOR = "chat_bg_color"
    private const val KEY_ACCENT_COLOR = "accent_color"
    private const val KEY_MATERIAL_YOU = "material_you"
    private const val KEY_TEXT_COLOR = "text_color"
    private const val WALLPAPER_FILE_NAME = "chat_wallpaper.jpg"

    /** bkz. `getTextScale`/`SettingsFragment` metin boyutu kaydırıcısı —
     *  sistemin kendi "Yazı tipi boyutu" ayarına EK, uygulamaya özel bir
     *  çarpan (bkz. `P2PApplication.onActivityPreCreated` — `Configuration.fontScale`
     *  üzerine bindirilir, sistem tercihini SIFIRLAMAZ). */
    const val TEXT_SCALE_MIN = 0.70f
    const val TEXT_SCALE_MAX = 1.60f
    const val TEXT_SCALE_DEFAULT = 1.0f

    /** bkz. `getUiScale` — genel arayüz yoğunluğu (density) çarpanı; metnin
     *  yanında dp tabanlı boşluk/simge boyutlarını da ölçekler (Android'in
     *  sistem geneli "Görüntü boyutu" ayarıyla AYNI mekanizma, bkz.
     *  `Configuration.densityDpi`). Çok dar bir aralıkta tutuluyor — aşırı
     *  bir yoğunluk değişikliği (ör. 2x) düzenin taşmasına/kırılmasına yol
     *  açabilir. */
    const val UI_SCALE_MIN = 0.75f
    const val UI_SCALE_MAX = 1.30f
    const val UI_SCALE_DEFAULT = 1.0f

    /** bkz. `FontChoice`/`getFontFamily` — seçilebilecek sistem font
     *  aileleri. Hepsi Android'in HER cihazda (bkz. platform `fonts.xml`
     *  geri dönüş zinciri) barındırdığı jenerik aile adları — hiçbir font
     *  dosyası paketlenmesi GEREKMEZ. */
    enum class FontChoice(val prefValue: String, val familyName: String?, val overlayStyleRes: Int) {
        DEFAULT("default", null, 0),
        SANS_MEDIUM("sans_medium", "sans-serif-medium", R.style.ThemeOverlay_P2PMessenger_Font_SansMedium),
        SANS_CONDENSED("sans_condensed", "sans-serif-condensed", R.style.ThemeOverlay_P2PMessenger_Font_SansCondensed),
        SERIF("serif", "serif", R.style.ThemeOverlay_P2PMessenger_Font_Serif),
        MONOSPACE("monospace", "monospace", R.style.ThemeOverlay_P2PMessenger_Font_Monospace),
        SANS_BLACK("sans_black", "sans-serif-black", R.style.ThemeOverlay_P2PMessenger_Font_SansBlack),
        CUSTOM("custom", null, R.style.ThemeOverlay_P2PMessenger_Font_Custom);

        companion object {
            fun fromPrefValue(value: String): FontChoice = entries.find { it.prefValue == value } ?: DEFAULT
        }
    }

    fun getTextScale(context: Context): Float {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        return prefs.getFloat(KEY_TEXT_SCALE, TEXT_SCALE_DEFAULT).coerceIn(TEXT_SCALE_MIN, TEXT_SCALE_MAX)
    }

    fun setTextScale(context: Context, scale: Float) {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        prefs.edit().putFloat(KEY_TEXT_SCALE, scale.coerceIn(TEXT_SCALE_MIN, TEXT_SCALE_MAX)).apply()
    }

    fun getUiScale(context: Context): Float {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        return prefs.getFloat(KEY_UI_SCALE, UI_SCALE_DEFAULT).coerceIn(UI_SCALE_MIN, UI_SCALE_MAX)
    }

    fun setUiScale(context: Context, scale: Float) {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        prefs.edit().putFloat(KEY_UI_SCALE, scale.coerceIn(UI_SCALE_MIN, UI_SCALE_MAX)).apply()
    }

    fun getFontChoice(context: Context): FontChoice {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        return FontChoice.fromPrefValue(prefs.getString(KEY_FONT_FAMILY, FontChoice.DEFAULT.prefValue) ?: FontChoice.DEFAULT.prefValue)
    }

    fun setFontChoice(context: Context, choice: FontChoice) {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        prefs.edit().putString(KEY_FONT_FAMILY, choice.prefValue).apply()
    }

    /**
     * Spec dışı, kullanıcı isteği: sohbet ekranının arka plan rengi — TEK
     * (kişi/grup başına AYRI değil) tercih. `null` = "tercih yok, tema
     * varsayılanı kullan" (bkz. `applyChatBackground`). Metin rengiyle İLGİSİ YOK — bkz. `getAccentColor`
     * dokümantasyonu, o amaçla kullanıcı isteği üzerine kaldırıldı.
     */
    fun getChatBackgroundColor(context: Context): Int? {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        if (isMaterialYou(context)) return null
        return if (prefs.contains(KEY_BG_COLOR)) prefs.getInt(KEY_BG_COLOR, 0) else null
    }

    fun setChatBackgroundColor(context: Context, color: Int?) {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        if (color == null) {
            prefs.edit().remove(KEY_BG_COLOR).apply()
        } else {
            prefs.edit().putInt(KEY_BG_COLOR, color).apply()
        }
    }

    /**
     * Spec dışı, kullanıcı isteği: TEK bir "vurgu" (accent) rengi — metin
     * rengi AYRICA seçilmez, her zaman bu rengin (ve ondan türetilen ton
     * ailesinin) üzerinde okunaklı olacak şekilde OTOMATİK siyah/beyaz
     * hesaplanır (bkz. `applyAccentColor` — Material'ın "content-based
     * dynamic color" motoru, ATC/HCT renk bilimiyle bunu ZATEN doğru
     * yapıyor, elle kontrast hesaplamaya GEREK YOK). Bu tek renkten TÜM
     * `colorPrimary*`/`colorSecondary*`/`colorTertiary*` rolleri (ve
     * dolayısıyla düğmeler, anahtarlar, kaydırıcılar, KENDİ mesaj
     * balonlarımız — bkz. `bubble_mine.xml` `?attr/colorPrimaryContainer`)
     * türetilir.
     */
    fun getAccentColor(context: Context): Int? {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        if (isMaterialYou(context)) return null
        return if (prefs.contains(KEY_ACCENT_COLOR)) prefs.getInt(KEY_ACCENT_COLOR, 0) else null
    }

    fun setAccentColor(context: Context, color: Int?) {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        if (color == null) {
            prefs.edit().remove(KEY_ACCENT_COLOR).apply()
        } else {
            prefs.edit().putInt(KEY_ACCENT_COLOR, color).apply()
        }
    }

    /** Material You açıkken sistem (duvarkağıdı) renkleri kullanılır, vurgu seçici devre dışıdır. */
    fun isMaterialYou(context: Context): Boolean =
        DynamicColors.isDynamicColorAvailable() &&
            context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).getBoolean(KEY_MATERIAL_YOU, true)

    fun setMaterialYou(context: Context, on: Boolean) {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).edit().putBoolean(KEY_MATERIAL_YOU, on).apply()
    }

    fun getTextColor(context: Context): Int? {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        if (isMaterialYou(context)) return null
        return if (prefs.contains(KEY_TEXT_COLOR)) prefs.getInt(KEY_TEXT_COLOR, 0) else null
    }

    fun setTextColor(context: Context, color: Int?) {
        val e = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).edit()
        if (color == null) e.remove(KEY_TEXT_COLOR) else e.putInt(KEY_TEXT_COLOR, color)
        e.apply()
    }

    /**
     * Below Android 12 there is no dynamic theme for `applyAccentColor` to
     * recolor: the chosen text color is painted onto the TextViews that use a
     * default theme text color (buttons, errors and bubble colors untouched).
     * ponytail: walks the tree on every layout pass; per-adapter painting if
     * that is ever measurably slow.
     */
    fun applyTextColorLegacy(activity: Activity) {
        if (DynamicColors.isDynamicColorAvailable()) return
        val color = getTextColor(activity) ?: return
        val decor = activity.window.decorView
        fun attr(a: Int) = MaterialColors.getColor(activity, a, 0) and 0xFFFFFF
        val defaults = setOf(
            attr(com.google.android.material.R.attr.colorOnSurface),
            attr(com.google.android.material.R.attr.colorOnBackground),
            attr(com.google.android.material.R.attr.colorOnSurfaceVariant),
            attr(android.R.attr.textColorPrimary),
            attr(android.R.attr.textColorSecondary),
        )
        fun walk(v: View) {
            if (v is android.widget.TextView && v !is android.widget.Button && v !is android.widget.EditText) {
                val cur = v.currentTextColor
                if ((cur and 0xFFFFFF) in defaults) {
                    val tinted = (color and 0xFFFFFF) or (cur and 0xFF000000.toInt())
                    if (tinted != cur) v.setTextColor(tinted)
                }
            }
            if (v is android.view.ViewGroup) for (i in 0 until v.childCount) walk(v.getChildAt(i))
        }
        decor.viewTreeObserver.addOnGlobalLayoutListener { walk(decor) }
    }

    /**
     * Spec dışı, kullanıcı isteği: duvarkağıdı resmi uygulamanın kendi
     * `filesDir`'inde SABİT bir dosya adıyla saklanır (bkz. profil fotoğrafı
     * deseni — `content://` URI'sini DEĞİL, kalıcı izin karmaşasına hiç
     * girmeden ham JPEG baytlarını tutuyoruz). Varlığı dosyanın kendisi
     * "seçilmiş mi" bilgisini taşır, ayrı bir SharedPreferences bayrağına
     * gerek yok.
     */
    fun chatWallpaperFile(context: Context): File = File(context.filesDir, WALLPAPER_FILE_NAME)

    /** Spec dışı, kullanıcı isteği ("birden fazla font içe aktarabilmeli,
     *  her biri kendi adıyla listede görünmeli"): tek sabit dosya yerine
     *  KİMLİKLİ bir font listesi. `id`, `newCustomFontId()`'nin ürettiği
     *  (kronolojik SIRALANABİLİR — 13 haneli epoch-ms) bir dizedir; ekranda
     *  gösterilen ad ayrı saklanır (SAF'ın verdiği gerçek dosya adı, bkz.
     *  `SettingsFragment.onFontPicked`). */
    data class CustomFont(val id: String, val displayName: String)

    private const val KEY_CUSTOM_FONTS = "custom_fonts"
    private const val KEY_ACTIVE_CUSTOM_FONT_ID = "active_custom_font_id"
    // `id` ve `displayName`'i TEK bir Set<String> girdisinde ayıran işaretçi —
    // bir dosya adında asla geçmeyecek bir kontrol karakteri (kullanıcı adı
    // her ne olursa olsun `` yazamaz).
    private const val CUSTOM_FONT_SEP = ''

    /** bkz. `customFontFile` — `content://` URI'yi DEĞİL, kalıcı izin
     *  karmaşasına hiç girmeden ham font baytlarını tutuyoruz. Her içe
     *  aktarılan font KENDİ dosyasını alır (`id` bazlı ad) — tek dosyanın
     *  üzerine yazmak öncekini sessizce kaybederdi. */
    fun customFontFile(context: Context, id: String): File = File(context.filesDir, "custom_font_$id.ttf")

    /** Yeni bir içe aktarma için kararlı, kronolojik sıralanabilir bir
     *  kimlik üretir — dosya adı VE listedeki sıralama anahtarı olarak
     *  kullanılır (bkz. `getCustomFonts` — id'ye göre string sıralama,
     *  epoch-ms hep aynı basamak sayısında olduğu sürece kronolojiktir). */
    fun newCustomFontId(): String = System.currentTimeMillis().toString()

    /** `id`'yi (ve dosyasını, çağıran taraf `customFontFile` ile ayrıca
     *  silmeli) listeye KAYDETMEZ, sadece görünen adı verilen listeye
     *  ekler — çağıran taraf font baytlarını dosyaya BAŞARIYLA yazdıktan
     *  SONRA çağırmalı (bkz. `SettingsFragment.onFontPicked` — kopyalama
     *  başarısız olursa listeye hiç eklenmez, yetim bir kayıt kalmaz). */
    fun registerCustomFont(context: Context, id: String, displayName: String) {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val current = prefs.getStringSet(KEY_CUSTOM_FONTS, emptySet()) ?: emptySet()
        val updated = HashSet(current)
        updated.add("$id$CUSTOM_FONT_SEP$displayName")
        prefs.edit().putStringSet(KEY_CUSTOM_FONTS, updated).apply()
    }

    /** İçe aktarılmış tüm fontlar, en eskiden en yeniye (bkz. `newCustomFontId`
     *  — id'ler epoch-ms olduğundan string sıralama zaman sırasıyla aynı). */
    fun getCustomFonts(context: Context): List<CustomFont> {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val raw = prefs.getStringSet(KEY_CUSTOM_FONTS, emptySet()) ?: emptySet()
        return raw.mapNotNull { entry ->
            val sep = entry.indexOf(CUSTOM_FONT_SEP)
            if (sep < 0) null else CustomFont(entry.substring(0, sep), entry.substring(sep + 1))
        }.sortedBy { it.id }
    }

    fun getActiveCustomFontId(context: Context): String? {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        return prefs.getString(KEY_ACTIVE_CUSTOM_FONT_ID, null)
    }

    fun setActiveCustomFontId(context: Context, id: String) {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        prefs.edit().putString(KEY_ACTIVE_CUSTOM_FONT_ID, id).apply()
    }

    /** bkz. `getFontChoice`/`FontChoice.CUSTOM` — o an SEÇİLİ olan içe
     *  aktarılmış fontun dosyası; kayıt bozulmuşsa (id silinmiş/eksik)
     *  `null` (çağıran taraf sessizce no-op yapar, bkz. `FontOverride.
     *  applyFile`'ın kendi dosya-yok kontrolü). */
    fun activeCustomFontFile(context: Context): File? =
        getActiveCustomFontId(context)?.let { customFontFile(context, it) }

    /** bkz. `getCustomFonts`/`getActiveCustomFontId` — o an seçili içe
     *  aktarılmış fontun görünen adı; kayıt bulunamazsa `null` (çağıran
     *  taraf jenerik bir yer tutucu adı gösterir). */
    fun activeCustomFontName(context: Context): String? {
        val id = getActiveCustomFontId(context) ?: return null
        return getCustomFonts(context).find { it.id == id }?.displayName
    }

    /** `clearChatWallpaper` — dosya silindiğinde bellekteki son decoded
     *  örneği de düşer (dialog'dan döndüğünde silinmiş duvarkağıdı, eski
     *  bitmap'le bir kez daha görünmesin). */
    fun clearChatWallpaper(context: Context) {
        chatWallpaperCache = null
        chatWallpaperKey = ""
        chatWallpaperFile(context).delete()
    }

    /**
     * `ChatActivity`/`GroupChatActivity` — ikisi de AYNI `activity_chat.xml`
     * düzenini kullanır (bkz. o dosyanın `imgChatWallpaper`/`rootChatLayout`
     * notu) — bu yüzden duvarkağıdı/arka plan rengi uygulama mantığı burada
     * TEK bir yerde, `onCreate` (ilk açılış) VE `onResume`'dan (Ayarlar'dan
     * dönüşte AYNI anda etkili olması için) çağrılır.
     */
    fun applyChatBackground(activity: Activity) {
        val wallpaperView = activity.findViewById<ImageView>(R.id.imgChatWallpaper) ?: return
        val wallpaperFile = chatWallpaperFile(activity)
        if (wallpaperFile.exists()) {
            val key = "${wallpaperFile.absolutePath}:${wallpaperFile.length()}:${wallpaperFile.lastModified()}"
            val cached = chatWallpaperCache
            val bitmap = if (cached != null && key == chatWallpaperKey) cached else try {
                decodeWallpaper(wallpaperFile.absolutePath, activity.resources.displayMetrics.widthPixels,
                    activity.resources.displayMetrics.heightPixels)
            } catch (e: Exception) {
                null
            }
            if (bitmap != null) {
                // Before the screen-sampled decode: the FULL-resolution file
                // was re-decoded on the UI thread at every onCreate/onResume
                // (both chat screens). One bitmap, refreshed only when the
                // wallpaper file itself changed, is all this view needs.
                chatWallpaperCache = bitmap
                chatWallpaperKey = key
                wallpaperView.setImageBitmap(bitmap)
                wallpaperView.visibility = View.VISIBLE
            } else {
                wallpaperView.visibility = View.GONE
            }
        } else {
            wallpaperView.visibility = View.GONE
        }
        val bgColor = getChatBackgroundColor(activity)
        val rootView = activity.findViewById<View>(R.id.rootChatLayout)
        if (bgColor != null) {
            rootView?.setBackgroundColor(bgColor)
        } else {
            rootView?.background = null
        }
    }

    /** Önbellek: SADECE son decoded örneği tek bitmap; eski girdisi GC'ye kalır. */
    private var chatWallpaperCache: Bitmap? = null
    private var chatWallpaperKey = ""

    /** Bounds sorgusu + `inSampleSize`: boyutu ekrana yeten çözünürlük yeter,
     *  dosyanın megapikseli belleğe girmiyor (bkz. MediaViewerActivity'deki
     *  aynı desen). */
    private fun decodeWallpaper(path: String, screenW: Int, screenH: Int): Bitmap? {
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeFile(path, bounds)
        if (bounds.outWidth <= 0 || bounds.outHeight <= 0) return null
        var sampleSize = 1
        while (bounds.outWidth / (sampleSize * 2) >= screenW && bounds.outHeight / (sampleSize * 2) >= screenH) {
            sampleSize *= 2
        }
        return BitmapFactory.decodeFile(path, BitmapFactory.Options().apply { inSampleSize = sampleSize })
    }

    /**
     * Spec dışı, kullanıcı isteği ("accent color picker, kullanılsın her
     * yerde, varyasyonlarla, metin her zaman rengin üzerinde okunaklı siyah/
     * beyaz olsun"): elle bir kontrast hesabı YAPMIYORUZ — Material
     * kütüphanesinin "content-based dynamic color" motoru (Google'ın HCT/
     * Material Color Utilities renk bilimi, Android 12+ duvarkağıdı tabanlı
     * dinamik rengin AYNISI ama duvarkağıdı yerine BİZİM verdiğimiz tek bir
     * "tohum" renkten) TEK bir renkten `colorPrimary`/`colorOnPrimary`/
     * `colorPrimaryContainer`/`colorOnPrimaryContainer`/`colorSecondary*`/
     * `colorTertiary*` (VARYASYONLAR) dahil TÜM tonal aileyi VE her birinin
     * üzerindeki metnin doğru kontrastını OTOMATİK üretir — bu, Google'ın
     * kendi (yoğun test edilmiş) renk motoru, elle siyah/beyaz hesaplamaktan
     * çok daha güvenilir. `setContentBasedSource(@ColorInt Int)` — Bitmap'e
     * HİÇ gerek yok, Material kütüphanesi tek bir renk int'ini doğrudan
     * tohum olarak kabul eden bir overload zaten sunuyor.
     *
     * BİLİNEN SINIR (kullanıcı geri bildirimi): maksimum saturasyonda bir
     * tohum seçilse BİLE sonuç hâlâ soluk görünebilir — bu, Android'in
     * içindeki (kapalı kaynak/OEM'e özel) dinamik renk üretim ardışık
     * düzeninin `colorPrimaryContainer` gibi AÇIK tonlu (yüksek "tone")
     * rollerde chroma'yı YAPISAL olarak kısıtlamasından kaynaklanıyor
     * (yüksek tone'da sRGB gamut'u ZATEN az chroma'ya izin verir) — tohum
     * rengin chroma'sını büyütmek bunu ÇÖZMEDİ (denendi, geri alındı),
     * çünkü darboğaz tohumda değil, o rolün TONUNDA. Şu an için düzeltilmiş
     * bir çözüm YOK.
     *
     * `P2PApplication.onCreate`'teki `DynamicColors.applyToActivitiesIfAvailable(this)`
     * (duvarkağıdı tabanlı, Android 12+) ile ÇAKIŞMAZ — bu ONDAN SONRA
     * (Activity oluşturulduğunda) çağrılır, kullanıcının AÇIKÇA seçtiği
     * vurgu rengi duvarkağıdı tabanlı otomatik rengin ÜZERİNE biner.
     */
    @android.annotation.SuppressLint("RestrictedApi")
    fun applyAccentColor(activity: Activity) {
        if (isMaterialYou(activity)) {
            DynamicColors.applyToActivityIfAvailable(activity)
            return
        }
        // Arka plan rengi yalnızca sohbet arka planıdır (bkz. applyChatBackground), palete girmez.
        val accent = getAccentColor(activity)
        val text = getTextColor(activity)
        val seed = accent ?: text ?: return
        if (!DynamicColors.isDynamicColorAvailable()) return
        DynamicColors.applyToActivityIfAvailable(activity, DynamicColorsOptions.Builder().setContentBasedSource(seed).build())
        if (text != null) {
            // Seçilen metin rengini temanın yüzey üstü metin rollerine taşır: dinamik
            // temanın renk kaynaklarının değerini çalışma anında değiştirir.
            com.google.android.material.color.ColorResourcesOverride.getInstance()?.applyIfPossible(
                activity,
                mapOf(
                    MR.material_personalized_color_on_surface to text,
                    MR.material_personalized_color_on_background to text,
                    MR.material_personalized_color_on_surface_variant to text,
                )
            )
        }
    }
}
