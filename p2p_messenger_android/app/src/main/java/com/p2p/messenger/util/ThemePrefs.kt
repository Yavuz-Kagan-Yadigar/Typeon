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
 * Appearance preferences. Pure user-experience settings, not part of the protocol.
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
    private const val WALLPAPER_PROCESSED_FILE_NAME = "chat_wallpaper_processed"
    private const val KEY_WALLPAPER_BLUR = "chat_wallpaper_blur_x10"
    private const val KEY_WALLPAPER_DARKNESS = "chat_wallpaper_darkness"
    private const val TAG = "ThemePrefs"

    /** Slider ranges. Blur is in tenths of a box radius, on the downscaled work bitmap
     *  (50 = radius 5.0). Darkness is in percent. */
    const val WALLPAPER_BLUR_MAX = 50
    const val WALLPAPER_DARKNESS_MAX = 90
    /** Longest side of the bitmap the blur runs on. The result is scaled back up. */
    private const val BLUR_WORK_SIDE = 256
    private const val PROCESSED_JPEG_QUALITY = 90

    /** Text size slider in SettingsFragment. It is an app-only multiplier ON TOP of the system
     *  font size setting (see `P2PApplication.onActivityPreCreated`: applied to `Configuration.fontScale`).
     *  It does not reset the system preference. */
    const val TEXT_SCALE_MIN = 0.70f
    const val TEXT_SCALE_MAX = 1.60f
    const val TEXT_SCALE_DEFAULT = 1.0f

    /** UI density multiplier (see `getUiScale`). It scales dp-based spacing and icon sizes along with the text.
     *  It uses the same mechanism as the system-wide display size setting (`Configuration.densityDpi`).
     *  The range is kept narrow: a large change (for example 2x) can overflow or break the layout. */
    const val UI_SCALE_MIN = 0.75f
    const val UI_SCALE_MAX = 1.30f
    const val UI_SCALE_DEFAULT = 1.0f

    /** Selectable system font families (see `FontChoice` / `getFontFamily`). They are generic family names
     *  that every Android device has (see the platform fallback chain in fonts.xml). No font file has to be bundled. */
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
     * Background colour of the chat screen. ONE preference for all chats (not per contact or group).
     * `null` means "no preference, use the theme default" (see `applyChatBackground`). It has no relation to
     * the text colour. See the `getAccentColor` docs.
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
     * ONE accent colour. The text colour is NOT chosen separately. Black or white is always computed
     * automatically to be readable on this colour and the tonal family derived from it (see `applyAccentColor`).
     * Material's content-based dynamic colour engine (HCT colour science) does this correctly already, so no
     * manual contrast maths is needed. From this one colour, all `colorPrimary*`, `colorSecondary*` and
     * `colorTertiary*` roles are derived. That covers buttons, switches, sliders, and my own message bubbles
     * (see `bubble_mine.xml`, `?attr/colorPrimaryContainer`).
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

    /** When Material You is on, system (wallpaper) colours are used and the accent picker is disabled. */
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
     * Below Android 12 there is no dynamic theme that `applyAccentColor` can recolour. The chosen text colour
     * is painted onto the TextViews that use a default theme text colour. Buttons, errors and bubble colours
     * are not touched.
     * ponytail: walks the tree once per burst of layout passes (50 ms debounce). Per-adapter painting, if this
     * is ever measurably slow.
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
        // Layout passes come in bursts (scrolling, typing). One walk runs after they settle,
        // instead of one per pass.
        val walkNow = Runnable { walk(decor) }
        decor.viewTreeObserver.addOnGlobalLayoutListener {
            decor.removeCallbacks(walkNow)
            decor.postDelayed(walkNow, 50)
        }
    }

    /**
     * The wallpaper image is kept under a FIXED file name in the app's own `filesDir`. The raw JPEG bytes are
     * stored, not a `content://` URI, so no persistent-permission handling is needed. The file's existence says
     * whether a wallpaper is set, so no separate SharedPreferences flag is needed.
     */
    fun chatWallpaperFile(context: Context): File = File(context.filesDir, WALLPAPER_FILE_NAME)

    /** Blurred and darkened copy of [chatWallpaperFile], next to it. It exists only while at least one slider
     *  is above 0. See [regenerateProcessedWallpaper]. */
    fun chatWallpaperProcessedFile(context: Context): File = File(context.filesDir, WALLPAPER_PROCESSED_FILE_NAME)

    /** Blur in tenths (0..[WALLPAPER_BLUR_MAX]). */
    fun getWallpaperBlur(context: Context): Int {
        val sp = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        return sp.getInt(KEY_WALLPAPER_BLUR, 0).coerceIn(0, WALLPAPER_BLUR_MAX)
    }

    fun getWallpaperDarkness(context: Context): Int =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .getInt(KEY_WALLPAPER_DARKNESS, 0).coerceIn(0, WALLPAPER_DARKNESS_MAX)

    fun setWallpaperEffects(context: Context, blur: Int, darkness: Int) {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).edit()
            .putInt(KEY_WALLPAPER_BLUR, blur.coerceIn(0, WALLPAPER_BLUR_MAX))
            .putInt(KEY_WALLPAPER_DARKNESS, darkness.coerceIn(0, WALLPAPER_DARKNESS_MAX))
            .apply()
    }

    /**
     * Computes the processed wallpaper ONCE from the stored sliders and writes it (or deletes it when both are 0).
     * It blocks, so call it from a background thread, and only when a slider is released or a new image is picked.
     * Chats never call this. They load whatever file it left behind.
     */
    @Synchronized
    fun regenerateProcessedWallpaper(context: Context) {
        val original = chatWallpaperFile(context)
        val processed = chatWallpaperProcessedFile(context)
        val blur = getWallpaperBlur(context)
        val dark = getWallpaperDarkness(context)
        if (!original.exists() || (blur == 0 && dark == 0)) {
            processed.delete()
            return
        }
        val dm = context.resources.displayMetrics
        val src = decodeWallpaper(original.absolutePath, dm.widthPixels, dm.heightPixels) ?: return
        val out = applyWallpaperEffects(src, blur, dark)
        val tmp = File(context.filesDir, "$WALLPAPER_PROCESSED_FILE_NAME.tmp")
        try {
            tmp.outputStream().use { out.compress(Bitmap.CompressFormat.JPEG, PROCESSED_JPEG_QUALITY, it) }
            if (!tmp.renameTo(processed)) throw java.io.IOException("rename failed")
            android.util.Log.i(TAG, "wallpaper processed file computed blur=$blur darkness=$dark ${out.width}x${out.height}")
        } finally {
            tmp.delete()
            if (out !== src) out.recycle()
            src.recycle()
        }
    }

    /** Cheap bitmap for the live preview while a slider is dragged. It is not stored. */
    fun wallpaperPreview(context: Context, blur: Int, darkness: Int, side: Int): Bitmap? {
        val original = chatWallpaperFile(context)
        if (!original.exists()) return null
        val src = decodeWallpaper(original.absolutePath, side, side) ?: return null
        return applyWallpaperEffects(src, blur, darkness)
    }

    /** Blur on a downscaled copy, scaled back to [src] size, then a black alpha overlay. */
    private fun applyWallpaperEffects(src: Bitmap, blur: Int, darkness: Int): Bitmap {
        if (blur == 0 && darkness == 0) return src
        var result = src
        if (blur > 0) {
            val k = BLUR_WORK_SIDE.toFloat() / maxOf(src.width, src.height)
            val w = maxOf(1, (src.width * k).toInt())
            val h = maxOf(1, (src.height * k).toInt())
            val small = Bitmap.createScaledBitmap(src, w, h, true)
            val px = IntArray(w * h)
            small.getPixels(px, 0, w, 0, 0, w, h)
            // Fractional radius: blend the blur at floor(r) and floor(r)+1.
            val r = blur / 10f
            val r0 = r.toInt()
            val f = r - r0
            val lo = px.copyOf()
            if (r0 > 0) blur3(lo, w, h, r0)
            if (f > 0f) {
                val hi = px.copyOf()
                blur3(hi, w, h, r0 + 1)
                for (i in px.indices) {
                    var o = 0
                    for (sh in intArrayOf(24, 16, 8, 0)) {
                        val a = (lo[i] ushr sh) and 255
                        val b = (hi[i] ushr sh) and 255
                        o = o or ((a + ((b - a) * f).toInt()) shl sh)
                    }
                    px[i] = o
                }
            } else {
                System.arraycopy(lo, 0, px, 0, px.size)
            }
            small.setPixels(px, 0, w, 0, 0, w, h)
            result = Bitmap.createScaledBitmap(small, src.width, src.height, true)
            if (small !== src && small !== result) small.recycle()
        }
        val canvasBmp = if (result.isMutable) result else result.copy(Bitmap.Config.ARGB_8888, true)
        if (canvasBmp !== result && result !== src) result.recycle()
        if (darkness > 0) {
            android.graphics.Canvas(canvasBmp).drawColor(android.graphics.Color.argb(darkness * 255 / 100, 0, 0, 0))
        }
        return canvasBmp
    }

    private fun blur3(px: IntArray, w: Int, h: Int, r: Int) {
        repeat(3) { // 3 box passes approximate a gaussian
            boxBlur(px, w, h, r, true)
            boxBlur(px, w, h, r, false)
        }
    }

    /** Running-sum box blur of radius [r] along rows ([horizontal]) or columns, with edges clamped. */
    private fun boxBlur(px: IntArray, w: Int, h: Int, r: Int, horizontal: Boolean) {
        val len = if (horizontal) w else h
        val lines = if (horizontal) h else w
        val step = if (horizontal) 1 else w
        val line = IntArray(len)
        val div = 2 * r + 1
        for (l in 0 until lines) {
            val base = if (horizontal) l * w else l
            for (i in 0 until len) line[i] = px[base + i * step]
            var a = 0; var rr = 0; var g = 0; var b = 0
            for (i in -r..r) {
                val c = line[i.coerceIn(0, len - 1)]
                a += c ushr 24; rr += (c shr 16) and 255; g += (c shr 8) and 255; b += c and 255
            }
            for (i in 0 until len) {
                px[base + i * step] = ((a / div) shl 24) or ((rr / div) shl 16) or ((g / div) shl 8) or (b / div)
                val add = line[(i + r + 1).coerceAtMost(len - 1)]
                val sub = line[(i - r).coerceAtLeast(0)]
                a += (add ushr 24) - (sub ushr 24)
                rr += ((add shr 16) and 255) - ((sub shr 16) and 255)
                g += ((add shr 8) and 255) - ((sub shr 8) and 255)
                b += (add and 255) - (sub and 255)
            }
        }
    }

    /**
     * Several custom fonts can be imported, and each one appears in the list under its own name. So instead of
     * one fixed file, there is a list of IDENTIFIED fonts. `id` is a string from `newCustomFontId()`
     * (sortable, a 13-digit epoch-ms value). The display name is stored separately. It is the real file name
     * given by SAF (see `SettingsFragment.onFontPicked`).
     */
    data class CustomFont(val id: String, val displayName: String)

    private const val KEY_CUSTOM_FONTS = "custom_fonts"
    private const val KEY_ACTIVE_CUSTOM_FONT_ID = "active_custom_font_id"
    // Separator between `id` and `displayName` in ONE Set<String> entry. It is a control character that can
    // never occur in a file name, so the display name cannot break the entry.
    private const val CUSTOM_FONT_SEP = ''

    /** See `customFontFile`. The raw font bytes are stored, not a `content://` URI. Each imported font gets its
     *  own file, named by its `id`. Writing over one shared file would silently lose the previous font. */
    fun customFontFile(context: Context, id: String): File {
        // Ids come from `newCustomFontId` (digits only). Anything else is refused, so a stored id can
        // never point outside filesDir.
        require(id.isNotEmpty() && id.all { it in '0'..'9' }) { "bad font id" }
        return File(context.filesDir, "custom_font_$id.ttf")
    }

    /** Makes a new stable, chronologically sortable id for an import. It is used as the file name AND as the sort key
     *  in the list (see `getCustomFonts`: string sort by id is chronological while epoch-ms has the same number of digits). */
    fun newCustomFontId(): String = System.currentTimeMillis().toString()

    /** Does NOT save `id` (or its file; the caller deletes the file with `customFontFile`) to the list. It only adds
     *  the display name to the list. The caller must call it AFTER the font bytes were written to the file successfully
     *  (see `SettingsFragment.onFontPicked`). If the copy fails, nothing is added to the list, and no orphan entry remains. */
    fun registerCustomFont(context: Context, id: String, displayName: String) {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val current = prefs.getStringSet(KEY_CUSTOM_FONTS, emptySet()) ?: emptySet()
        val updated = HashSet(current)
        updated.add("$id$CUSTOM_FONT_SEP$displayName")
        prefs.edit().putStringSet(KEY_CUSTOM_FONTS, updated).apply()
    }

    /** All imported fonts, from oldest to newest (see `newCustomFontId`: ids are epoch-ms, so string order is time order). */
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

    /** See `getFontChoice` / `FontChoice.CUSTOM`. The file of the custom font that is currently SELECTED. If the record
     *  is broken (id removed or missing), it returns `null`. The caller then does nothing (see `FontOverride.applyFile`'s
     *  own missing-file check). */
    fun activeCustomFontFile(context: Context): File? =
        getActiveCustomFontId(context)?.let { runCatching { customFontFile(context, it) }.getOrNull() }

    /** See `getCustomFonts` / `getActiveCustomFontId`. The display name of the custom font that is currently selected.
     *  If no record is found, `null`. The caller then shows a generic placeholder name. */
    fun activeCustomFontName(context: Context): String? {
        val id = getActiveCustomFontId(context) ?: return null
        return getCustomFonts(context).find { it.id == id }?.displayName
    }

    /** `clearChatWallpaper`. When the file is deleted, the last decoded bitmap in memory is dropped too, so a deleted
     *  wallpaper cannot show again from the old bitmap after the dialog returns. */
    fun clearChatWallpaper(context: Context) {
        chatWallpaperCache = null
        chatWallpaperKey = ""
        chatWallpaperFile(context).delete()
        chatWallpaperProcessedFile(context).delete()
    }

    /**
     * ChatActivity and GroupChatActivity use the SAME `activity_chat.xml` layout (see the `imgChatWallpaper` /
     * `rootChatLayout` notes in that file). So the wallpaper and background colour logic lives in ONE place here.
     * It is called from `onCreate` (first open) and from `onResume` (so a change made in Settings applies at once on return).
     */
    fun applyChatBackground(activity: Activity) {
        val wallpaperView = activity.findViewById<ImageView>(R.id.imgChatWallpaper) ?: return
        // The processed file (if any) is the only thing loaded here. The size and mtime key below means a new
        // file invalidates the memory cache.
        val wallpaperFile = chatWallpaperProcessedFile(activity).takeIf { it.exists() && chatWallpaperFile(activity).exists() }
            ?: chatWallpaperFile(activity)
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
                // The bitmap is decoded at the screen's sampled size. The full-resolution file used to be
                // decoded on the UI thread at every onCreate and onResume of both chat screens. One bitmap,
                // refreshed only when the wallpaper file itself changes, is all this view needs.
                chatWallpaperCache = bitmap
                chatWallpaperKey = key
                wallpaperView.setImageBitmap(bitmap)
                // Fixed full-display height: the keyboard shrinks the root, not the picture
                // (the overflow under the keyboard is clipped).
                @Suppress("DEPRECATION")
                wallpaperView.layoutParams.height = android.util.DisplayMetrics()
                    .also { activity.windowManager.defaultDisplay.getRealMetrics(it) }.heightPixels
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

    /** Cache: only the last decoded sample, as one bitmap. The older entry is left for the GC. */
    private var chatWallpaperCache: Bitmap? = null
    private var chatWallpaperKey = ""

    /** Bounds query, then `inSampleSize`. A resolution that fits the screen is enough, so the file's full megapixels
     *  are never loaded into memory (same pattern as MediaViewerActivity). */
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
     * Accent colour picker, applied everywhere, with variations. The text is always black or white, readable on the colour.
     * No manual contrast maths is done. Material's content-based dynamic colour engine (Material Color Utilities,
     * HCT) builds the whole tonal family from ONE seed colour: `colorPrimary`, `colorOnPrimary`, `colorPrimaryContainer`,
     * `colorOnPrimaryContainer`, `colorSecondary*` and `colorTertiary*` (the variants). It also computes the text
     * contrast on each of them. It is the same engine as Android 12+ wallpaper dynamic colour, but seeded with the
     * colour we choose. `setContentBasedSource(@ColorInt Int)` takes that colour directly, so no Bitmap is needed.
     *
     * Known limit: even at maximum saturation, the result can still look pale. Android's dynamic colour pipeline
     * limits chroma structurally in the light tonal roles such as `colorPrimaryContainer` (at high tone the sRGB
     * gamut allows little chroma anyway). The seed's chroma does not change this: the limit is in the tone of
     * that role, not in the seed. No fix is known yet.
     *
     * It does not conflict with the wallpaper-based dynamic colour of `P2PApplication.onCreate`
     * (`DynamicColors.applyToActivitiesIfAvailable(this)`, Android 12+). This runs AFTER that, when the
     * Activity is created, so the accent the user chose is layered on top of the automatic colour.
     */
    @android.annotation.SuppressLint("RestrictedApi")
    fun applyAccentColor(activity: Activity) {
        if (isMaterialYou(activity)) {
            DynamicColors.applyToActivityIfAvailable(activity)
            return
        }
        // The background colour is only the chat background (see applyChatBackground). It is not in the palette.
        val accent = getAccentColor(activity)
        val text = getTextColor(activity)
        val seed = accent ?: text ?: return
        if (!DynamicColors.isDynamicColorAvailable()) return
        DynamicColors.applyToActivityIfAvailable(activity, DynamicColorsOptions.Builder().setContentBasedSource(seed).build())
        if (text != null) {
            // Moves the chosen text colour to the theme's on-surface text roles. It changes the value of the
            // dynamic theme's colour resources at run time.
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
