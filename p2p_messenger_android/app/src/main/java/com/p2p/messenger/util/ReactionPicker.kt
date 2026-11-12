package com.p2p.messenger.util

import android.content.Context
import android.view.Gravity
import android.view.ViewGroup
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import androidx.emoji2.emojipicker.EmojiPickerView
import androidx.appcompat.app.AlertDialog
import com.p2p.messenger.R

/**
 * "mesajlara uzun basarak emoji bırakabilmeliyiz
 * WhatsApp'taki gibi" → sonra: "react kısmında TAM SİSTEM emoji seçici ile
 * açılsın."
 *
 * Bu yüzden ilk sürümdeki sabit altı emojilik sıra KALDIRILDI; yerine
 * `androidx.emoji2.emojipicker.EmojiPickerView` — kategorileri, arama
 * çubuğu, "son kullanılanlar" ve ten rengi varyantlarıyla tam ızgara.
 *
 * NOT (kapsam sınırı): Android, bir uygulamanın klavyenin KENDİ emoji
 * panelini doğrudan açmasına izin veren bir genel API sunmuyor — böyle bir
 * intent/`InputMethodManager` çağrısı yok. `EmojiPickerView`, platformun
 * kendi emoji verisini (emoji2) kullanan resmi ve en yakın karşılığı.
 *
 * SUNUM: ortalanmış bir `AlertDialog`. Önce `BottomSheetDialog` denendi;
 * kullanıcı "garip ve çok aşağıda açılıyor" diye bildirdi ve haklıydı —
 * Material'ın alt sayfası GENİŞ ekranlarda azami bir genişliğe sıkışıyor,
 * bu yüzden tablette ekranın alt ortasında dar, yüzen ve altı kesik bir
 * panel olarak çıkıyordu. Ortalanmış dialog her iki form faktöründe de
 * öngörülebilir: ekranın ortasında, ekrana göre ölçeklenen sabit bir
 * kutu.
 */
object ReactionPicker {

    /**
     * [onPick] boş dize alırsa "tepkimi kaldır" demektir.
     *
     * [showRemove]: mesajda ZATEN tepki varsa sayfanın üstüne bir "kaldır"
     * düğmesi eklenir. Neden "aynı emojiye tekrar dokun = kaldır" değil:
     * özet dizesi (bkz. Rust `reactions_summary`) hangi emojinin BENİM
     * olduğunu taşımıyor, sadece toplamları taşıyor. Bunu bilmek için
     * protokole kişi bazlı bir liste eklemek gerekirdi; açık bir "kaldır"
     * düğmesi aynı işi protokolü büyütmeden yapıyor.
     */
    fun show(context: Context, showRemove: Boolean, onPick: (String) -> Unit) {
        val density = context.resources.displayMetrics.density
        val metrics = context.resources.displayMetrics

        val container = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
        }

        container.addView(TextView(context).apply {
            setText(R.string.title_pick_reaction)
            textSize = 16f
            val pad = (16 * density).toInt()
            setPadding(pad, pad, pad, pad / 2)
        })

        // `dialog` aşağıda kuruluyor; dinleyiciler ona buradan erişebilsin.
        var dialogRef: AlertDialog? = null

        if (showRemove) {
            container.addView(Button(context).apply {
                setText(R.string.action_remove_reaction)
                val margin = (16 * density).toInt()
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
                ).apply {
                    marginStart = margin
                    gravity = Gravity.START
                }
                setOnClickListener {
                    onPick("")
                    dialogRef?.dismiss()
                }
            })
        }

        container.addView(EmojiPickerView(context).apply {
            // Sabit yükseklik: `WRAP_CONTENT` bir ızgarada anlamsız, sayfa
            // ya kapanacak kadar kısalıyor ya ekranı tamamen kaplıyordu.
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                (340 * density).toInt()
            )
            setOnEmojiPickedListener { picked ->
                onPick(picked.emoji)
                dialogRef?.dismiss()
            }
        })

        val dialog = AlertDialog.Builder(context)
            .setView(container)
            .setNegativeButton(android.R.string.cancel, null)
            .create()
        dialogRef = dialog
        dialog.show()
        // Izgara `WRAP_CONTENT` ile ya kapanacak kadar kısalıyor ya ekranı
        // kaplıyor — genişliği ekrana göre AÇIKÇA veriyoruz (tablette
        // uçtan uca yayılmasın, telefonda da dar kalmasın).
        dialog.window?.setLayout(
            minOf((metrics.widthPixels * 0.92f).toInt(), (420 * density).toInt()),
            ViewGroup.LayoutParams.WRAP_CONTENT
        )
    }
}
