package com.p2p.messenger.util

import android.graphics.Typeface
import java.lang.reflect.Field
import java.lang.reflect.Modifier

/**
 * Spec dışı, kullanıcı isteği ("break material, doesn't matter, force
 * font on all UI"): Ayarlar'daki font seçimini GERÇEKTEN her yere
 * uygulamak için — Material bileşenlerinin kendi type scale'inin
 * ÖTESİNDE (bkz. themes.xml `appFontFamily`/`TextAppearance.P2PMessenger.*`
 * — SADECE Material'ın `?attr/textAppearanceBodyLarge` vb. ÖZNİTELİK
 * ZİNCİRİNİ kullanan görünümleri kapsar), bu uygulamada YAYGIN olan
 * (sohbet balonu metinleri, Ayarlar açıklama satırları, vb.) hiçbir
 * `textAppearance`/`fontFamily` BELİRTMEYEN düz `TextView`'lar da dahil
 * OLMAK ÜZERE — Android'in kendi varsayılan `Typeface` statik alanlarını
 * (`Typeface.DEFAULT`/`DEFAULT_BOLD`/`SANS_SERIF`/`SERIF`/`MONOSPACE`) VE
 * stil bazlı varsayılan dizisini (`Typeface.sDefaults`, `Typeface.
 * defaultFromStyle(int)`'in kaynağı) reflection ile DEĞİŞTİRİR — bu,
 * hiçbir şey belirtilmemiş HER `TextView`'ın çözümlediği "varsayılan"
 * fontun ta kendisidir.
 *
 * `final` bir statik alanı `Field.set` ile değiştirmek normalde
 * `IllegalAccessException` fırlatır — bu yüzden önce `Field` nesnesinin
 * KENDİ `modifiers` alanından `FINAL` bayrağı temizleniyor (klasik, yaygın
 * kullanılan bir teknik — ör. Calligraphy ve benzeri font-değiştirme
 * kütüphaneleri).
 *
 * BİLİNEN SINIR: bu TAMAMEN belgelenmemiş, resmi olmayan bir teknik —
 * bazı Android sürümlerinde/OEM ROM'larında (özellikle Android'in gizli
 * API kısıtlamaları nedeniyle) `SecurityException`/`NoSuchFieldException`
 * fırlatabilir. Her adım TEK TEK try/catch ile sarmalı: bir alan
 * değiştirilemezse sessizce atlanır, diğerleri yine de denenir — kısmi
 * bir başarı (ör. `DEFAULT` değişir ama `sDefaults` değişmez) tam
 * başarısızlıktan iyidir, ve HİÇBİRİ ÇÖKMEYE yol açmaz. Material
 * bileşenlerinin (buton/toolbar/dropdown) kendi type scale'i zaten AYRI
 * (ve garantili çalışan) `appFontFamily` tema özniteliği yoluyla
 * kapsandığından, bu fonksiyonun asıl hedefi o boşluktaki düz TextView'lar
 * — o yüzden burada bir başarısızlık, uygulamayı YARI fontlanmış bırakır,
 * hiç fontlanmamış değil.
 */
object FontOverride {
    /** `familyName`: `null`/boş ise no-op (varsayılan sistem fontuna
     *  dönmenin GERÇEK yolu süreç yeniden başlatmaktır — bu fonksiyon
     *  SADECE ileri yönde bir değiştirme uygular, geri almaz; bkz.
     *  P2PApplication/SettingsFragment çağıran taraf notu — zaten bir
     *  önceki override varsa üzerine YENİ bir tane yazmak zararsız). */
    fun apply(familyName: String?) {
        if (familyName.isNullOrBlank()) return
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
            // Bu cihazda/Android sürümünde reflection engellenmiş olabilir —
            // sessizce vazgeç, diğer alanlar yine de denenir.
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
            // bkz. yukarısı — sessizce vazgeç.
        }
    }

    private fun makeAccessibleAndNonFinal(field: Field) {
        field.isAccessible = true
        try {
            val modifiersField = Field::class.java.getDeclaredField("modifiers")
            modifiersField.isAccessible = true
            modifiersField.setInt(field, field.modifiers and Modifier.FINAL.inv())
        } catch (e: Exception) {
            // Android 9+ bazı sürümlerde `Field.modifiers` alanının KENDİSİ
            // gizli API kısıtlamasına takılabilir — bu durumda `field.set`
            // yine de denenir (bazı ART sürümlerinde `final` statik
            // referans-tipi alanlar pratikte hâlâ değiştirilebiliyor),
            // başarısız olursa çağıran taraf (`replaceStaticField`/
            // `replaceDefaultsArray`) zaten kendi try/catch'iyle bunu
            // sessizce yutuyor.
        }
    }
}
