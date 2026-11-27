package com.p2p.messenger.util

import android.content.Context
import android.view.Gravity
import android.widget.ArrayAdapter
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.Spinner
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.app.AppCompatDelegate
import androidx.core.os.LocaleListCompat
import com.p2p.messenger.R

/** The UI languages, and the first-start popup that asks for one before any other prompt. */
object LanguagePicker {
    val codes = arrayOf("en", "tr", "es", "ru", "uk", "hi", "ar", "zh-CN")
    val labels = arrayOf("English", "Türkçe", "Español", "Русский", "Українська", "हिन्दी", "العربية", "简体中文")
    private const val KEY = "language_chosen"

    private fun prefs(c: Context) = c.getSharedPreferences("language", Context.MODE_PRIVATE)

    fun isChosen(c: Context) = prefs(c).getBoolean(KEY, false)

    /** The app's language, or the system's when none is set. */
    fun currentIndex(c: Context): Int {
        val current = AppCompatDelegate.getApplicationLocales().toLanguageTags()
            .ifEmpty { c.resources.configuration.locales[0].language }
        return codes.indexOfFirst { current.substringBefore('-') == it.substringBefore('-') }.coerceAtLeast(0)
    }

    private const val TAG_KEY = "language_tag"

    fun apply(context: Context, index: Int) {
        prefs(context).edit().putString(TAG_KEY, codes[index]).commit()
        AppCompatDelegate.setApplicationLocales(LocaleListCompat.forLanguageTags(codes[index]))
    }

    /** [context] in the picked language. Android 12 and lower give the app language to activities only,
     *  so services, receivers and workers take their strings from this. */
    fun localized(context: Context): Context {
        if (android.os.Build.VERSION.SDK_INT >= 33) return context
        val tag = prefs(context).getString(TAG_KEY, null) ?: return context
        val config = android.content.res.Configuration(context.resources.configuration)
        config.setLocale(java.util.Locale.forLanguageTag(tag))
        return context.createConfigurationContext(config)
    }

    fun showFirstRun(activity: AppCompatActivity, done: () -> Unit = {}): AlertDialog {
        val pad = (24 * activity.resources.displayMetrics.density).toInt()
        val spinner = Spinner(activity).apply {
            adapter = ArrayAdapter(activity, android.R.layout.simple_spinner_dropdown_item, labels)
            setSelection(currentIndex(activity))
        }
        val row = LinearLayout(activity).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(pad, pad / 2, pad, 0)
            addView(ImageView(activity).apply { setImageResource(R.drawable.ic_globe) })
            addView(spinner, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        }
        return AlertDialog.Builder(activity)
            .setTitle(R.string.lbl_language)
            .setView(row)
            .setCancelable(false)
            .setPositiveButton(android.R.string.ok) { _, _ ->
                // Stored first: applying the language recreates the activity.
                prefs(activity).edit().putBoolean(KEY, true).commit()
                apply(activity, spinner.selectedItemPosition)
                done()
            }
            .show()
    }
}
