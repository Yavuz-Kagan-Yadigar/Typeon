package com.p2p.messenger.util

import android.graphics.Typeface
import java.lang.reflect.Field
import java.lang.reflect.Modifier

/**
 * Forces the font chosen in Settings onto EVERYTHING, not only the places that use the Material text styles. The theme
 * (themes.xml `appFontFamily` and `TextAppearance.P2PMessenger.*`) covers views that use Material's
 * `?attr/textAppearanceBodyLarge` and similar attributes. This class also covers plain `TextView`s that set no
 * `textAppearance` or `fontFamily` at all (chat bubble text, Settings description lines, and so on). It replaces Android's
 * own default Typeface static fields (`Typeface.DEFAULT`, `DEFAULT_BOLD`, `SANS_SERIF`, `SERIF`, `MONOSPACE`) and the
 * style-based default array (`Typeface.sDefaults`, the source of `Typeface.defaultFromStyle(int)`), using reflection.
 * That array is the "default" font every TextView resolves to when nothing is set.
 *
 * Setting a `final` static field with `Field.set` normally throws IllegalAccessException. So first the FINAL flag is
 * cleared from the `Field` object's own `modifiers` field. This is a common technique, used by font-changing libraries
 * such as Calligraphy.
 *
 * KNOWN LIMIT: this is a completely undocumented, unofficial technique. On some Android versions and OEM ROMs (because of
 * Android's hidden API restrictions) it can throw SecurityException or NoSuchFieldException. Each step is wrapped in its
 * own try/catch. If one field cannot be replaced, it is skipped and the others are still tried. A partial success (for
 * example, `DEFAULT` changes but `sDefaults` does not) is better than a full failure, and none of them crash the app.
 * Material components (button, toolbar, dropdown) have their own type scale, covered by the `appFontFamily` theme attribute,
 * which is guaranteed to work. So the target of this function is the plain TextViews in between. A failure here leaves the
 * app half-styled, not unstyled.
 */
object FontOverride {
    /** The font every TextView must carry. null means the system font. */
    @Volatile private var current: Typeface? = null

    /** Last resort for views that bypass the theme and the statics (adapter rows, toolbar subtitles): keeps the whole window's
     *  TextViews on [current], with bold and italic preserved. */
    fun forceOnWindow(activity: android.app.Activity) {
        if (hooked.put(activity, true) != null) return
        val root = activity.window.decorView
        // One walk after a burst of layout passes (scrolling, typing), as ThemePrefs.applyTextColorLegacy does.
        val walkNow = Runnable { forceTree(root) }
        root.viewTreeObserver.addOnGlobalLayoutListener {
            if (current == null) return@addOnGlobalLayoutListener
            root.removeCallbacks(walkNow)
            root.postDelayed(walkNow, 50)
        }
    }

    private val hooked = java.util.WeakHashMap<android.app.Activity, Boolean>()

    private fun forceTree(v: android.view.View) {
        val base = current ?: return
        if (v is android.widget.TextView) {
            val style = v.typeface?.style ?: 0
            val want = Typeface.create(base, style)
            if (v.typeface !== want) v.typeface = want
        } else if (v is android.view.ViewGroup) {
            for (i in 0 until v.childCount) forceTree(v.getChildAt(i))
        }
    }

    private var cachedFile: Pair<Pair<String, Long>, Typeface>? = null

    /** `familyName` null or empty is a no-op. The REAL way back to the system font is a process restart. This function only
     *  applies a change going forward, it does not revert. The caller (see P2PApplication and SettingsFragment) is noted. If an
     *  earlier override exists, writing a new one over it is harmless. */
    fun apply(familyName: String?) {
        remapSansSerif(null)
        if (familyName.isNullOrBlank()) {
            restoreOriginals()
            return
        }
        val newTypeface = try {
            Typeface.create(familyName, Typeface.NORMAL)
        } catch (e: Exception) {
            return
        }
        val newBoldTypeface = try {
            Typeface.create(familyName, Typeface.BOLD)
        } catch (e: Exception) {
            newTypeface
        }
        applyTypeface(newTypeface, newBoldTypeface)
    }

    /** See `apply(String?)`. It runs the same reflection chain, but loads the Typeface from a file (`Typeface.createFromFile`)
     *  instead of `familyName`. A missing or invalid font file is a no-op, and does not crash. */
    fun applyFile(file: java.io.File) {
        // P2PApplication calls this on EVERY Activity creation. `createFromFile` has no cache, so every call would read the font
        // again and allocate a new native Typeface. For the same file, the previous one is reused.
        val key = file.path to file.lastModified()
        val newTypeface = cachedFile?.takeIf { it.first == key }?.second ?: try {
            Typeface.createFromFile(file).also { cachedFile = key to it }
        } catch (e: Exception) {
            return
        }
        val newBoldTypeface = try {
            // `createFromFile` takes no style parameter (it has only the File and String overloads). The bold variant is derived from
            // the loaded Typeface with `Typeface.create(base, style)`, the same purpose as the `familyName` path in `apply(String?)`.
            Typeface.create(newTypeface, Typeface.BOLD)
        } catch (e: Exception) {
            newTypeface
        }
        applyTypeface(newTypeface, newBoldTypeface)
        remapSansSerif(newTypeface)
    }

    /**
     * Framework and AppCompat styles (action bar title, EditText, the default type scale) ask for a font
     * with a name, such as fontFamily="sans-serif". That name is resolved through the system font map
     * (sSystemFontMap), not through Typeface.DEFAULT, so the imported font does not reach it.
     * The sans-serif entries are replaced with the loaded font. null puts the originals back, when switching
     * to the system font. The monospace and serif entries are not touched.
     */
    private var originalSansEntries: Map<String, Typeface>? = null
    private var originalDefaultTypeface: Typeface? = null

    private fun remapSansSerif(typeface: Typeface?) {
        try {
            val field = Typeface::class.java.getDeclaredField("sSystemFontMap")
            field.isAccessible = true
            @Suppress("UNCHECKED_CAST")
            val map = field.get(null) as? MutableMap<String, Typeface> ?: return
            val originals = originalSansEntries
                ?: map.filterKeys { !it.startsWith("monospace") && !it.startsWith("serif") }.toMap().also { originalSansEntries = it }
            for ((name, original) in originals) {
                map[name] = typeface?.let { Typeface.create(it, original.style) } ?: original
            }
            // Unknown family names (themes.xml `p2p-imported-font`) fall back to the private `sDefaultTypeface`, not `Typeface.DEFAULT`.
            // Otherwise dialogs and EditTexts that resolve the theme's fontFamily by name kept the system font.
            if (typeface != null) map["p2p-imported-font"] = typeface else map.remove("p2p-imported-font")
            try {
                val f = Typeface::class.java.getDeclaredField("sDefaultTypeface")
                makeAccessibleAndNonFinal(f)
                if (originalDefaultTypeface == null) originalDefaultTypeface = f.get(null) as? Typeface
                (typeface ?: originalDefaultTypeface)?.let { f.set(null, it) }
            } catch (e: Exception) {
            }
        } catch (e: Exception) {
        // See `replaceStaticField`. If hidden API access is blocked, give up silently.
        }
    }

    /** Shared by `apply` and `applyFile`. It gathers the six reflection calls (`replaceStaticField` x5 and `replaceDefaultsArray` x1)
     *  in one place, so they are not duplicated. */
    private val STATIC_FIELDS = listOf("DEFAULT", "DEFAULT_BOLD", "SANS_SERIF", "SERIF", "MONOSPACE")
    /** The system's own typefaces, captured before the first replacement. */
    private var originalStatics: Map<String, Typeface>? = null
    private var originalDefaults: Array<Typeface>? = null

    private fun captureOriginals() {
        if (originalStatics != null) return
        originalStatics = STATIC_FIELDS.mapNotNull { name ->
            try {
                val field = Typeface::class.java.getDeclaredField(name).apply { isAccessible = true }
                (field.get(null) as? Typeface)?.let { name to it }
            } catch (e: Exception) {
                null
            }
        }.toMap()
        originalDefaults = try {
            val field = Typeface::class.java.getDeclaredField("sDefaults").apply { isAccessible = true }
            @Suppress("UNCHECKED_CAST")
            (field.get(null) as? Array<Typeface>)?.clone()
        } catch (e: Exception) {
            null
        }
    }

    /** Back to the system font without a process restart. Until then, every view with no explicit `fontFamily` kept the old custom font. */
    private fun restoreOriginals() {
        current = null
        for ((name, typeface) in originalStatics ?: return) replaceStaticField(name, typeface)
        try {
            val field = Typeface::class.java.getDeclaredField("sDefaults").apply { isAccessible = true }
            @Suppress("UNCHECKED_CAST")
            val defaults = field.get(null) as? Array<Typeface> ?: return
            originalDefaults?.copyInto(defaults)
        } catch (e: Exception) {
        }
    }

    private fun applyTypeface(newTypeface: Typeface, newBoldTypeface: Typeface) {
        captureOriginals()
        current = newTypeface
        replaceStaticField("DEFAULT", newTypeface)
        replaceStaticField("DEFAULT_BOLD", newBoldTypeface)
        replaceStaticField("SANS_SERIF", newTypeface)
        replaceStaticField("SERIF", newTypeface)
        replaceStaticField("MONOSPACE", newTypeface)
        replaceDefaultsArray(newTypeface)
    }

    private fun replaceStaticField(fieldName: String, typeface: Typeface) {
        try {
            val field = Typeface::class.java.getDeclaredField(fieldName)
            makeAccessibleAndNonFinal(field)
            field.set(null, typeface)
        } catch (e: Exception) {
        // On this device or Android version, reflection may be blocked. Give up silently, and the other fields are still tried.
        }
    }

    private fun replaceDefaultsArray(typeface: Typeface) {
        try {
            val field = Typeface::class.java.getDeclaredField("sDefaults")
            makeAccessibleAndNonFinal(field)
            @Suppress("UNCHECKED_CAST")
            val defaults = field.get(null) as? Array<Typeface> ?: return
            for (i in defaults.indices) {
                defaults[i] = Typeface.create(typeface, i)
            }
        } catch (e: Exception) {
        // See above. Give up silently.
        }
    }

    private fun makeAccessibleAndNonFinal(field: Field) {
        field.isAccessible = true
        try {
            val modifiersField = Field::class.java.getDeclaredField("modifiers")
            modifiersField.isAccessible = true
            modifiersField.setInt(field, field.modifiers and Modifier.FINAL.inv())
        } catch (e: Exception) {
        // On some Android 9+ versions, the `Field.modifiers` field itself may hit the hidden API restriction. In that case `field.set`
        // is still tried. On some ART versions, `final` static reference-type fields can in practice still be changed. If it fails,
        // the caller (`replaceStaticField` / `replaceDefaultsArray`) already swallows it silently with its own try/catch.
        }
    }
}
