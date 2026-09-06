package com.p2p.messenger.ui

import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.activity.OnBackPressedCallback
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.p2p.messenger.R
import com.p2p.messenger.util.AppLock
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Spec dışı, kullanıcı isteği: uygulamayı açmak için şifre ekranı.
 *
 * İki modu var ve modu KENDİSİ seçer (çağıran tarafın bilmesi gerekmez,
 * bkz. `AppLock.guard`): henüz hiç şifre kurulmamışsa "oluştur" (iki alan,
 * doğrulamalı), kurulmuşsa "gir".
 *
 * `showWhenLocked`/`excludeFromRecents` gibi ek sertleştirmeler bilinçli
 * olarak kapsam dışı — bu ekran, telefonu eline alan birine karşı arayüz
 * düzeyinde bir engel; asıl gizlilik garantisi kimlik/mesaj anahtarlarının
 * Android Keystore ile korunmasında (bkz. util.KeystoreCrypto).
 */
class AppLockActivity : AppCompatActivity() {

    private var createMode = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_app_lock)

        createMode = !AppLock.hasPassword(this)

        val title = findViewById<TextView>(R.id.txt_app_lock_title)
        val desc = findViewById<TextView>(R.id.txt_app_lock_desc)
        val password = findViewById<EditText>(R.id.edt_app_lock_password)
        val confirm = findViewById<EditText>(R.id.edt_app_lock_confirm)
        val error = findViewById<TextView>(R.id.txt_app_lock_error)
        val submit = findViewById<Button>(R.id.btn_app_lock_submit)

        if (createMode) {
            title.setText(R.string.title_app_lock_create)
            desc.setText(R.string.msg_app_lock_create)
            confirm.visibility = View.VISIBLE
            submit.setText(R.string.action_app_lock_save)
        } else {
            title.setText(R.string.title_app_lock_unlock)
            desc.setText(R.string.msg_app_lock_unlock)
            confirm.visibility = View.GONE
            submit.setText(R.string.action_app_lock_unlock)
        }

        submit.setOnClickListener {
            error.visibility = View.GONE
            val entered = password.text.toString()
            if (entered.isBlank()) {
                showError(error, getString(R.string.error_app_lock_empty))
                return@setOnClickListener
            }
            if (createMode && entered != confirm.text.toString()) {
                showError(error, getString(R.string.error_app_lock_mismatch))
                return@setOnClickListener
            }
            // PBKDF2 KASITLI olarak yavaş (bkz. AppLock.ITERATIONS) — ana
            // thread'de çalıştırılırsa görünür bir donma yaratır.
            submit.isEnabled = false
            lifecycleScope.launch(Dispatchers.IO) {
                val ok = if (createMode) {
                    AppLock.setPassword(this@AppLockActivity, entered)
                } else {
                    AppLock.verify(this@AppLockActivity, entered)
                }
                withContext(Dispatchers.Main) {
                    submit.isEnabled = true
                    if (ok) {
                        AppLock.markUnlocked()
                        finish()
                    } else {
                        password.text.clear()
                        showError(error, getString(R.string.error_app_lock_wrong))
                    }
                }
            }
        }

        // Geri tuşu kilidi ATLAYAMAZ: kilit ekranı kapanacaksa uygulamadan
        // tamamen çıkılır (arkadaki Activity yığını görünür kalmamalı).
        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                AppLock.promptClosed()
                finishAffinity()
            }
        })
    }

    /**
     * Emniyet ağı: `AppLock.guard` kilit ekranını başlatırken "zaten
     * gösteriliyor" bayrağını kaldırır ve o bayrak normalde ya kilit
     * açılınca ya geri tuşuyla temizlenir. Sistem bu Activity'yi başka bir
     * yolla yok ederse (bellek baskısı, `finish()` dışı bir yol) bayrak
     * asılı kalır ve `guard` bir daha ASLA kilit ekranı açmazdı. Kilit
     * hâlâ kapalıysa burada temizliyoruz; açıldıysa `markUnlocked` zaten
     * temizlemiş olur ve bu çağrı zararsız bir no-op'tur.
     */
    override fun onDestroy() {
        super.onDestroy()
        AppLock.promptClosed()
    }

    private fun showError(view: TextView, message: String) {
        view.text = message
        view.visibility = View.VISIBLE
    }
}
