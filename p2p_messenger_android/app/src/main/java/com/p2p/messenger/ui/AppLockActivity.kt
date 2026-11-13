package com.p2p.messenger.ui

import android.os.Bundle
import android.view.KeyEvent
import android.view.View
import android.view.inputmethod.EditorInfo
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
 * The password screen for opening the app.
 *
 * It has two modes, and the screen chooses the mode itself (the caller does not need to know; see `AppLock.guard`). If no password has ever
 * been set, it is "create" mode (two fields, validated). If one is set, it is "enter" mode.
 *
 * Extra hardening such as `showWhenLocked` or `excludeFromRecents` is deliberately out of scope. This screen is an interface-level barrier
 * against someone who picks up the phone. The real privacy guarantee lies in the identity and message keys being protected by the Android
 * Keystore (see util.KeystoreCrypto).
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
            val wait = AppLock.retryWaitSeconds(this)
            if (!createMode && wait > 0) {
                showError(error, getString(R.string.error_app_lock_wait, wait))
                return@setOnClickListener
            }
            if (createMode && entered.length < AppLock.MIN_PASSWORD_LENGTH) {
                showError(error, getString(R.string.error_app_lock_short, AppLock.MIN_PASSWORD_LENGTH))
                return@setOnClickListener
            }
            if (createMode && entered != confirm.text.toString()) {
                showError(error, getString(R.string.error_app_lock_mismatch))
                return@setOnClickListener
            }
            // PBKDF2 is deliberately slow (see AppLock.ITERATIONS). Run on the main thread, it would freeze the UI visibly.
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
                        AppLock.clearFailedAttempts(this@AppLockActivity)
                        AppLock.markUnlocked()
                        finish()
                    } else {
                        if (!createMode) AppLock.noteFailedAttempt(this@AppLockActivity)
                        password.text.clear()
                        showError(error, getString(R.string.error_app_lock_wrong))
                    }
                }
            }
        }

        // The keyboard's done or OK key also unlocks. In create mode the first field moves to the confirm field, and the last field submits.
        if (createMode) password.imeOptions = EditorInfo.IME_ACTION_NEXT
        val submitOnIme = TextView.OnEditorActionListener { _, actionId, event ->
            val enterKey = event?.keyCode == KeyEvent.KEYCODE_ENTER && event.action == KeyEvent.ACTION_DOWN
            if (actionId == EditorInfo.IME_ACTION_DONE || actionId == EditorInfo.IME_ACTION_GO || enterKey) {
                if (submit.isEnabled) submit.performClick()
                true
            } else {
                false
            }
        }
        (if (createMode) confirm else password).setOnEditorActionListener(submitOnIme)

        // The back key cannot skip the lock. If the lock screen is closing, the app exits completely, so no activity from the stack stays visible behind it.
        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                finishAffinity()
            }
        })
    }

    /** A second lock screen may have unlocked the app meanwhile. */
    override fun onStart() {
        super.onStart()
        if (AppLock.isUnlocked()) finish()
    }

    private fun showError(view: TextView, message: String) {
        view.text = message
        view.visibility = View.VISIBLE
    }
}
