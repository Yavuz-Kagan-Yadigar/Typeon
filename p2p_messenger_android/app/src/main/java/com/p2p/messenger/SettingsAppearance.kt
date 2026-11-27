package com.p2p.messenger

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.InputType
import android.view.LayoutInflater
import android.view.Menu
import android.view.MenuInflater
import android.view.MenuItem
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatDelegate
import androidx.core.os.LocaleListCompat
import androidx.core.view.MenuProvider
import androidx.fragment.app.Fragment
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import com.google.android.material.color.MaterialColors
import com.google.android.material.switchmaterial.SwitchMaterial
import com.p2p.messenger.ui.QrScanActivity
import com.p2p.messenger.util.ArchiveKeyManager
import com.p2p.messenger.service.P2PService
import com.p2p.messenger.ui.PendingMessagesActivity
import com.p2p.messenger.ui.StorageActivity
import com.p2p.messenger.util.AppLock
import com.p2p.messenger.util.AppRestarter
import com.p2p.messenger.util.AvatarUtil
import com.p2p.messenger.util.ImagePreview
import com.p2p.messenger.util.MAX_FOREIGN_URI_BYTES
import com.p2p.messenger.util.NotificationPrefs
import com.p2p.messenger.util.ThemePrefs
import com.p2p.messenger.util.copyToCapped
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID
import com.p2p.messenger.SettingsFragment.Companion.ACCOUNT_DELETE_WAIT_MS
import com.p2p.messenger.SettingsFragment.Companion.AVATAR_JPEG_QUALITY
import com.p2p.messenger.SettingsFragment.Companion.AVATAR_MAX_DIMENSION
import com.p2p.messenger.SettingsFragment.Companion.MAX_FONT_BYTES
import com.p2p.messenger.SettingsFragment.Companion.TEXT_SCALE_STEPS
import com.p2p.messenger.SettingsFragment.Companion.UI_SCALE_STEPS
import com.p2p.messenger.SettingsFragment.Companion.WALLPAPER_JPEG_QUALITY
import com.p2p.messenger.SettingsFragment.Companion.WALLPAPER_MAX_DIMENSION
import com.p2p.messenger.SettingsFragment.Companion.closestStepIndex

// SettingsFragment, appearance cards: theme, language, chat look, wallpaper and fonts.

/**
 * Text size and interface size sliders, plus the system font picker. See `ThemePrefs` / `P2PApplication.applyScalePreferences`. Both are applied in
 * `onActivityPreCreated`, before the Activity's `onCreate` runs. The reason is the same as for the OLED switch: a change takes effect only when the next
 * Activity is created. So ALL THREE call `requireActivity().recreate()` when the value is released (slider) or chosen (dropdown). Not during the drag
 * (that would mean dozens of needless recreates per second), only at the final value.
 */
internal fun SettingsFragment.setupAppearanceControls(view: View) {
    val textScaleValue = view.findViewById<TextView>(R.id.text_scale_value)
    val textScaleSlider = view.findViewById<android.widget.SeekBar>(R.id.text_scale_slider)
    // See `TEXT_SCALE_STEPS` / `closestStepIndex`: a whole-number index (not a floating-point `stepSize`). This avoids the Material Slider crash at its root.
    textScaleSlider.max = TEXT_SCALE_STEPS.size - 1
    val currentTextScale = ThemePrefs.getTextScale(requireContext())
    textScaleSlider.progress = closestStepIndex(TEXT_SCALE_STEPS, currentTextScale)
    textScaleValue.text = formatScalePercent(TEXT_SCALE_STEPS[closestStepIndex(TEXT_SCALE_STEPS, currentTextScale)])
    textScaleSlider.setOnSeekBarChangeListener(object : android.widget.SeekBar.OnSeekBarChangeListener {
        override fun onProgressChanged(bar: android.widget.SeekBar, progress: Int, fromUser: Boolean) {
            textScaleValue.text = formatScalePercent(TEXT_SCALE_STEPS[progress])
        }
        override fun onStartTrackingTouch(bar: android.widget.SeekBar) {}
        override fun onStopTrackingTouch(bar: android.widget.SeekBar) {
            ThemePrefs.setTextScale(requireContext(), TEXT_SCALE_STEPS[bar.progress])
            requireActivity().recreate()
        }
    })

    val uiScaleValue = view.findViewById<TextView>(R.id.ui_scale_value)
    val uiScaleSlider = view.findViewById<android.widget.SeekBar>(R.id.ui_scale_slider)
    uiScaleSlider.max = UI_SCALE_STEPS.size - 1
    val currentUiScale = ThemePrefs.getUiScale(requireContext())
    uiScaleSlider.progress = closestStepIndex(UI_SCALE_STEPS, currentUiScale)
    uiScaleValue.text = formatScalePercent(UI_SCALE_STEPS[closestStepIndex(UI_SCALE_STEPS, currentUiScale)])
    uiScaleSlider.setOnSeekBarChangeListener(object : android.widget.SeekBar.OnSeekBarChangeListener {
        override fun onProgressChanged(bar: android.widget.SeekBar, progress: Int, fromUser: Boolean) {
            uiScaleValue.text = formatScalePercent(UI_SCALE_STEPS[progress])
        }
        override fun onStartTrackingTouch(bar: android.widget.SeekBar) {}
        override fun onStopTrackingTouch(bar: android.widget.SeekBar) {
            ThemePrefs.setUiScale(requireContext(), UI_SCALE_STEPS[bar.progress])
            requireActivity().recreate()
        }
    })

    // See ThemePrefs.FontChoice: the order must match the displayed name list exactly (index-based mapping). `CUSTOM` is NOT in this list: it is not a directory.
    // `getActiveCustomFontId` tracks which of the N imported fonts from `ThemePrefs.getCustomFonts()` is selected (see the dialog setup below).
    // A custom font shows its real imported name, and several imports are supported.
    val fontChoices = ThemePrefs.FontChoice.entries.filter { it != ThemePrefs.FontChoice.CUSTOM }
    val fontLabels = arrayOf(
        getString(R.string.lbl_font_default),
        getString(R.string.lbl_font_sans_medium),
        getString(R.string.lbl_font_sans_condensed),
        getString(R.string.lbl_font_serif),
        getString(R.string.lbl_font_monospace),
        getString(R.string.lbl_font_sans_black)
    )
    // Replaces a `MaterialAutoCompleteTextView` with `setSimpleItems` by a plain `Button` and `AlertDialog.setSingleChoiceItems`. The exposed dropdown
    // showed only the default item on a real device, and its popup behaviour cannot be verified in this environment, so a simpler mechanism is used.
    // This list is not filtered: ALL options are always shown.
    //
    // Known limit: the list offers only the generic aliases that every Android device guarantees (`sans-serif`, `serif`, `monospace`, plus weight and width
    // variants). There is no general, official Android API to enumerate a manufacturer's branded or downloaded font names (for example 'One UI Sans' or a
    // downloaded Google Fonts family), so those never appear here. The 'Default' option still uses the device's CURRENT system default (even if the user
    // changed it in manufacturer settings), because no override is applied.
    val fontValueText = view.findViewById<TextView>(R.id.font_family_value)
    fun currentFontLabel(): String {
        val choice = ThemePrefs.getFontChoice(requireContext())
        return if (choice == ThemePrefs.FontChoice.CUSTOM) {
            // See `ThemePrefs.activeCustomFontName`: the real name of the selected font among several imported ones. If the record is broken (the id was deleted),
            // it falls back to the generic name.
            ThemePrefs.activeCustomFontName(requireContext()) ?: getString(R.string.lbl_font_custom)
        } else {
            fontLabels[fontChoices.indexOf(choice).coerceAtLeast(0)]
        }
    }
    fontValueText.text = currentFontLabel()
    view.findViewById<Button>(R.id.btn_pick_font).setOnClickListener {
        val currentChoice = ThemePrefs.getFontChoice(requireContext())
        val activeCustomId = ThemePrefs.getActiveCustomFontId(requireContext())
        val customFonts = ThemePrefs.getCustomFonts(requireContext())
        // Dialog rows: [0] 'Import', [1..fontChoices.size] the built-in fonts, then any imported fonts. Each imported font has its own name
        // (see `ThemePrefs.CustomFont.displayName`): the real font name, not 'custom', and several may exist.
        val dialogLabels = arrayOf(getString(R.string.lbl_font_import)) + fontLabels +
            customFonts.map { it.displayName }.toTypedArray()
        val currentIndex = if (currentChoice == ThemePrefs.FontChoice.CUSTOM) {
            val i = customFonts.indexOfFirst { it.id == activeCustomId }
            if (i >= 0) 1 + fontChoices.size + i else 0
        } else {
            fontChoices.indexOf(currentChoice).coerceAtLeast(0) + 1
        }
        AlertDialog.Builder(requireContext())
            .setTitle(R.string.lbl_font_family)
            .setSingleChoiceItems(dialogLabels, currentIndex) { dialog, position ->
                when {
                    position == 0 -> {
                        // 'Import a .ttf file…' selects no font. It closes the dialog and opens the file picker.
                        dialog.dismiss()
                        AppLock.beginTrustedExcursion()
                        pickFontLauncher.launch(arrayOf("font/ttf", "font/otf", "application/x-font-ttf", "application/octet-stream", "*/*"))
                    }
                    position <= fontChoices.size -> {
                        // See `fontChoices`: position 1 and up maps to index = position - 1.
                        val chosen = fontChoices[position - 1]
                        if (chosen != currentChoice) {
                            ThemePrefs.setFontChoice(requireContext(), chosen)
                            fontValueText.text = fontLabels[position - 1]
                            // Forces the font on all UI: see the `FontOverride` docs. It replaces Android's default Typeface at once (`P2PApplication.onCreate` runs only at
                            // process start, so without this call the change would show only after the next full app restart). `recreate()` then redraws this Activity with the
                            // updated default Typeface.
                            com.p2p.messenger.util.FontOverride.apply(chosen.familyName)
                            requireActivity().recreate()
                        }
                        dialog.dismiss()
                    }
                    else -> {
                        // One of the fonts imported earlier was selected (see `dialogLabels`: these rows are offset in `customFonts` by fontChoices.size).
                        val cf = customFonts[position - 1 - fontChoices.size]
                        if (!(currentChoice == ThemePrefs.FontChoice.CUSTOM && cf.id == activeCustomId)) {
                            ThemePrefs.setFontChoice(requireContext(), ThemePrefs.FontChoice.CUSTOM)
                            ThemePrefs.setActiveCustomFontId(requireContext(), cf.id)
                            fontValueText.text = cf.displayName
                            com.p2p.messenger.util.FontOverride.applyFile(ThemePrefs.customFontFile(requireContext(), cf.id))
                            requireActivity().recreate()
                        }
                        dialog.dismiss()
                    }
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }
}

/** Language picker. AppCompatDelegate.setApplicationLocales
 *  persists the choice itself (see AndroidManifest AppLocalesMetadataHolderService)
 *  and recreates all activities; the explicit recreate() below matches this
 *  screen's own font/color pickers for immediate visual feedback. */
internal fun SettingsFragment.setupLanguageControl(view: View) {
    val picker = com.p2p.messenger.util.LanguagePicker
    view.findViewById<TextView>(R.id.language_value).text = picker.labels[picker.currentIndex(requireContext())]
    view.findViewById<Button>(R.id.btn_pick_language).setOnClickListener {
        AlertDialog.Builder(requireContext())
            .setTitle(R.string.lbl_language)
            .setSingleChoiceItems(picker.labels, picker.currentIndex(requireContext())) { dialog, position ->
                picker.apply(requireContext(), position)
                dialog.dismiss()
                requireActivity().recreate()
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }
}

internal fun SettingsFragment.formatScalePercent(scale: Float): String = getString(R.string.lbl_scale_percent, (scale * 100).toInt())

/**
 * ONE accent colour, used everywhere (buttons, switches, sliders, and our own message bubbles), with variations (see `ThemePrefs.applyAccentColor`,
 * Material's content-based dynamic colour engine). The text colour is NOT chosen separately: it is always computed as black or white, whichever is
 * readable on that colour. The background colour is valid for both the general UI and the chat screen (see `ThemePrefs.applyChatBackground`).
 * The colour picker is a full HSV picker (see `HsvColorPickerDialog`) and needs NO external library: this build cannot be verified in this environment,
 * so no new Gradle dependency is added. Both colours (accent and background) change the whole app's theme, like OLED and the font,
 * so `recreate()` is needed after the choice.
 */
internal fun SettingsFragment.setupChatAppearanceControls(view: View) {
    val bgSwatch = view.findViewById<View>(R.id.chat_bg_color_swatch)
    val accentSwatch = view.findViewById<View>(R.id.accent_color_swatch)
    val textSwatch = view.findViewById<View>(R.id.text_color_swatch)
    val wallpaperThumb = view.findViewById<ImageView>(R.id.chat_wallpaper_thumb)
    val btnRemoveWallpaper = view.findViewById<Button>(R.id.btn_remove_chat_wallpaper)

    fun swatchDrawable(color: Int?): android.graphics.drawable.Drawable {
        return android.graphics.drawable.GradientDrawable().apply {
            shape = android.graphics.drawable.GradientDrawable.OVAL
            setColor(color ?: MaterialColors.getColor(bgSwatch, com.google.android.material.R.attr.colorSurfaceVariant))
            setStroke((1.5f * resources.displayMetrics.density).toInt(), MaterialColors.getColor(bgSwatch, com.google.android.material.R.attr.colorOutline))
        }
    }

    fun refreshSwatches() {
        bgSwatch.background = swatchDrawable(ThemePrefs.getChatBackgroundColor(requireContext()))
        accentSwatch.background = swatchDrawable(ThemePrefs.getAccentColor(requireContext()))
        textSwatch.background = swatchDrawable(ThemePrefs.getTextColor(requireContext()))
    }

    val blurRow = view.findViewById<View>(R.id.wallpaper_blur_row)
    val darknessRow = view.findViewById<View>(R.id.wallpaper_darkness_row)
    val blurSlider = view.findViewById<android.widget.SeekBar>(R.id.wallpaper_blur_slider)
    val darknessSlider = view.findViewById<android.widget.SeekBar>(R.id.wallpaper_darkness_slider)
    val blurValue = view.findViewById<TextView>(R.id.wallpaper_blur_value)
    val darknessValue = view.findViewById<TextView>(R.id.wallpaper_darkness_value)

    // Cheap downscaled preview while dragging (off the main thread, newest wins).
    var previewJob: kotlinx.coroutines.Job? = null
    fun previewEffects() {
        val app = requireContext().applicationContext
        val blur = blurSlider.progress
        val dark = darknessSlider.progress
        previewJob?.cancel()
        previewJob = viewLifecycleOwner.lifecycleScope.launch(Dispatchers.Default) {
            val bmp = ThemePrefs.wallpaperPreview(app, blur, dark, 160) ?: return@launch
            withContext(Dispatchers.Main) { wallpaperThumb.setImageBitmap(bmp) }
        }
    }

    fun refreshWallpaperPreview() {
        val file = ThemePrefs.chatWallpaperFile(requireContext())
        if (file.exists()) {
            blurSlider.progress = ThemePrefs.getWallpaperBlur(requireContext())
            darknessSlider.progress = ThemePrefs.getWallpaperDarkness(requireContext())
            blurValue.text = "%.1f".format(blurSlider.progress / 10f)
            darknessValue.text = "${darknessSlider.progress}%"
            previewEffects() // sets the thumbnail from a small decode, off the main thread
            wallpaperThumb.visibility = View.VISIBLE
            btnRemoveWallpaper.visibility = View.VISIBLE
            blurRow.visibility = View.VISIBLE
            darknessRow.visibility = View.VISIBLE
        } else {
            wallpaperThumb.visibility = View.GONE
            btnRemoveWallpaper.visibility = View.GONE
            blurRow.visibility = View.GONE
            darknessRow.visibility = View.GONE
        }
    }

    // On release: store values, compute the processed file once, off the main thread.
    fun seekListener(onProgress: (Int, Boolean) -> Unit) = object : android.widget.SeekBar.OnSeekBarChangeListener {
        override fun onProgressChanged(bar: android.widget.SeekBar, progress: Int, fromUser: Boolean) = onProgress(progress, fromUser)
        override fun onStartTrackingTouch(bar: android.widget.SeekBar) {}
        override fun onStopTrackingTouch(bar: android.widget.SeekBar) {
            val app = requireContext().applicationContext
            ThemePrefs.setWallpaperEffects(app, blurSlider.progress, darknessSlider.progress)
            lifecycleScope.launch(Dispatchers.IO) {
                try {
                    ThemePrefs.regenerateProcessedWallpaper(app)
                } catch (e: Exception) {
                    com.p2p.messenger.util.Log.w("SettingsFragment", "wallpaper effects failed", e)
                }
            }
        }
    }
    blurSlider.setOnSeekBarChangeListener(seekListener { value, fromUser ->
        blurValue.text = "%.1f".format(value / 10f)
        if (fromUser) previewEffects()
    })
    darknessSlider.setOnSeekBarChangeListener(seekListener { value, fromUser ->
        darknessValue.text = "${value}%"
        if (fromUser) previewEffects()
    })

    refreshSwatches()
    refreshWallpaperPreview()

    view.findViewById<Button>(R.id.btn_pick_chat_bg_color).setOnClickListener {
        com.p2p.messenger.util.HsvColorPickerDialog.show(
            requireContext(), R.string.title_pick_bg_color, ThemePrefs.getChatBackgroundColor(requireContext())
        ) { picked ->
            ThemePrefs.setChatBackgroundColor(requireContext(), picked)
            refreshSwatches()
            requireActivity().recreate()
        }
    }
    // `ThemePrefs.applyAccentColor` rides on dynamic colour (Android 12+).
    if (!com.google.android.material.color.DynamicColors.isDynamicColorAvailable()) {
        view.findViewById<Button>(R.id.btn_pick_accent_color).visibility = View.GONE
        accentSwatch.visibility = View.GONE
    }
    view.findViewById<Button>(R.id.btn_pick_text_color).setOnClickListener {
        com.p2p.messenger.util.HsvColorPickerDialog.show(
            requireContext(), R.string.title_pick_text_color, ThemePrefs.getTextColor(requireContext())
        ) { picked ->
            ThemePrefs.setTextColor(requireContext(), picked)
            refreshSwatches()
            requireActivity().recreate()
        }
    }
    val myBtn = view.findViewById<SwitchMaterial>(R.id.material_you_switch)
    val accentBtn = view.findViewById<Button>(R.id.btn_pick_accent_color)
    fun syncAccentEnabled() {
        val on = ThemePrefs.isMaterialYou(requireContext())
        for (b in listOf(accentBtn, view.findViewById<Button>(R.id.btn_pick_chat_bg_color), view.findViewById<Button>(R.id.btn_pick_text_color))) {
            b.isEnabled = !on
        }
        for (sw in listOf(accentSwatch, bgSwatch, textSwatch)) sw.alpha = if (on) 0.4f else 1f
    }
    if (!com.google.android.material.color.DynamicColors.isDynamicColorAvailable()) {
        myBtn.visibility = View.GONE
        (myBtn.parent as View).visibility = View.GONE
    }
    myBtn.isChecked = ThemePrefs.isMaterialYou(requireContext())
    syncAccentEnabled()
    myBtn.setOnCheckedChangeListener { _, on ->
        ThemePrefs.setMaterialYou(requireContext(), on)
        syncAccentEnabled()
        requireActivity().recreate()
    }
    view.findViewById<Button>(R.id.btn_pick_accent_color).setOnClickListener {
        com.p2p.messenger.util.HsvColorPickerDialog.show(
            requireContext(), R.string.title_pick_accent_color, ThemePrefs.getAccentColor(requireContext())
        ) { picked ->
            ThemePrefs.setAccentColor(requireContext(), picked)
            refreshSwatches()
            requireActivity().recreate()
        }
    }
    view.findViewById<Button>(R.id.btn_pick_chat_wallpaper).setOnClickListener {
        AppLock.beginTrustedExcursion()
        pickWallpaperLauncher.launch(arrayOf("image/*"))
    }
    btnRemoveWallpaper.setOnClickListener {
        ThemePrefs.clearChatWallpaper(requireContext())
        refreshWallpaperPreview()
    }
}

/**
 * Same `content://` to local file copy pattern as `onAvatarPicked`. The difference: this is ONLY a local UI preference, sent to nobody
 * (see ThemePrefs.chatWallpaperFile), so Rust is not involved.
 */
internal fun SettingsFragment.onChatWallpaperPicked(uri: Uri) {
    // Off the fragment: `requireContext()` on the worker threw once the
    // screen was gone.
    val app = requireContext().applicationContext
    lifecycleScope.launch(Dispatchers.IO) {
        val tempFile = File(File(app.cacheDir, "wallpaper").apply { mkdirs() }, UUID.randomUUID().toString())
        try {
            // Foreign `content://` URI: cap the bytes actually streamed into the cache (see ImagePreview.copyToCapped and GroupChatActivity).
            val copied = app.contentResolver.openInputStream(uri)?.use { input ->
                input.copyToCapped(tempFile, MAX_FOREIGN_URI_BYTES)
            } ?: false
            if (!copied) throw java.io.IOException("File could not be opened")
            // Not a readable image: the catch below shows the error toast.
            val compressed = ImagePreview.compressFile(tempFile, WALLPAPER_MAX_DIMENSION, WALLPAPER_JPEG_QUALITY)
                ?: throw java.io.IOException("not an image")
            ThemePrefs.chatWallpaperFile(app).writeBytes(compressed)
            // New image: rebuild the processed copy with the current slider values.
            ThemePrefs.regenerateProcessedWallpaper(app)
            // Thumbnail only (160 px): a small decode here, not the full image on the main thread.
            val thumbBitmap = ThemePrefs.wallpaperPreview(app, ThemePrefs.getWallpaperBlur(app), ThemePrefs.getWallpaperDarkness(app), 160)
            withContext(Dispatchers.Main) {
                view?.let { v ->
                    val thumb = v.findViewById<ImageView>(R.id.chat_wallpaper_thumb)
                    val btnRemove = v.findViewById<Button>(R.id.btn_remove_chat_wallpaper)
                    val file = ThemePrefs.chatWallpaperFile(app)
                    if (file.exists()) {
                        thumb.setImageBitmap(thumbBitmap)
                        thumb.visibility = View.VISIBLE
                        btnRemove.visibility = View.VISIBLE
                        v.findViewById<View>(R.id.wallpaper_blur_row).visibility = View.VISIBLE
                        v.findViewById<View>(R.id.wallpaper_darkness_row).visibility = View.VISIBLE
                    }
                }
            }
        } catch (e: Exception) {
            withContext(Dispatchers.Main) {
                Toast.makeText(app, R.string.error_attachment_open_failed, Toast.LENGTH_SHORT).show()
            }
        } finally {
            tempFile.delete()
        }
    }
}

/**
 * See `onChatWallpaperPicked`: a RAW byte copy from a `content://` URI into the local `filesDir`. No threads or coroutines: synchronous, a simple
 * `openInputStream` → `copyTo`. Font files are small (usually under 1 MB), so no block-size optimisation is needed.
 *
 * Each pick is copied to its OWN new id (`newCustomFontId`) and ADDED to the list, so earlier imported fonts stay. The shown name is the REAL file name
 * that SAF provides (`OpenableColumns.DISPLAY_NAME`). If the copy fails (or SAF gives no name and the fallback path also fails), no record is added or selected,
 * so no orphan list entry remains.
 */
internal fun SettingsFragment.onFontPicked(uri: Uri) {
    // Copies up to 32 MB: off the main thread.
    val ctx = requireContext().applicationContext
    lifecycleScope.launch {
        val displayName = withContext(Dispatchers.IO) { copyPickedFont(ctx, uri) }
        if (displayName == null) {
            Toast.makeText(ctx, R.string.error_attachment_open_failed, Toast.LENGTH_SHORT).show()
            return@launch
        }
        val id = displayName.first
        val file = ThemePrefs.customFontFile(ctx, id)
        val name = displayName.second
        ThemePrefs.registerCustomFont(ctx, id, name)
        ThemePrefs.setFontChoice(ctx, ThemePrefs.FontChoice.CUSTOM)
        ThemePrefs.setActiveCustomFontId(ctx, id)
        view?.findViewById<TextView>(R.id.font_family_value)?.text = name
        com.p2p.messenger.util.FontOverride.applyFile(file)
        activity?.recreate()
    }
}

/** Blocking part of [onFontPicked]: (font id, display name), or null on failure. */
internal fun SettingsFragment.copyPickedFont(context: android.content.Context, uri: Uri): Pair<String, String>? {
    val id = ThemePrefs.newCustomFontId()
    val file = ThemePrefs.customFontFile(context, id)
    try {
        context.contentResolver.openInputStream(uri)?.use { input ->
            // The '*/*' picker accepts any file. Only files with a font signature (TrueType, OpenType or collection) and a reasonable size are copied, so an
            // accidentally picked video cannot fill filesDir and a broken file does not enter the list. `readNBytes` needs API 33+; minSdk is 26, so a short
            // file hits EOFException.
            val head = ByteArray(4).also { java.io.DataInputStream(input).readFully(it) }
            val magicOk = (
                head.contentEquals(byteArrayOf(0, 1, 0, 0)) ||
                    String(head, Charsets.ISO_8859_1) in setOf("OTTO", "true", "ttcf"))
            if (!magicOk) throw java.io.IOException("not a font file")
            file.outputStream().use { out ->
                out.write(head)
                val buf = ByteArray(64 * 1024)
                var total = head.size.toLong()
                while (true) {
                    val n = input.read(buf)
                    if (n < 0) break
                    total += n
                    if (total > MAX_FONT_BYTES) throw java.io.IOException("font too large")
                    out.write(buf, 0, n)
                }
            }
        } ?: return null
        return id to (queryDisplayName(context, uri) ?: file.name)
    } catch (e: Exception) {
        // See `onChatWallpaperPicked`: must not crash, passes silently. A half-copied file is also dropped. It is never added to the list, so it cannot be
        // selected, but it must not stay on disk as an orphan.
        file.delete()
        return null
    }
}

/** Reads the REAL file name from the `content://` URI that SAF gave (see `onFontPicked`: the font list shows this name instead of 'Custom').
 *  Some providers may leave this column empty; if it returns `null`, the caller falls back to its own file name. */
internal fun SettingsFragment.queryDisplayName(context: android.content.Context, uri: Uri): String? {
    return try {
        context.contentResolver.query(uri, arrayOf(android.provider.OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cursor ->
            val idx = cursor.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
            if (idx >= 0 && cursor.moveToFirst()) cursor.getString(idx) else null
        }
    } catch (e: Exception) {
        null
    }
}
