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
import com.p2p.messenger.util.NotificationPrefs
import com.p2p.messenger.util.ThemePrefs
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID

class SettingsFragment : Fragment() {

    companion object {
        /** Which settings cards are open. Process-wide so an appearance change
         *  (which recreates the activity) does not fold the card the user was in. */
        private val expandedSections = mutableSetOf("profile")
        /** bkz. ChatActivity PREVIEW_MAX_DIMENSION notu — kullanıcı
         *  tarafından istenen profil fotoğrafı standardı: 720p/%85 JPEG
         *  (sohbet eki önizlemelerinden — 480p — daha büyük, çünkü profil
         *  fotoğrafı tam ekran/daha büyük gösterilebilir). */
        private const val AVATAR_MAX_DIMENSION = 720
        /** bkz. `performDeleteAccount`. */
        private const val ACCOUNT_DELETE_WAIT_MS = 15_000L
        /** bkz. `onFontPicked` — büyük CJK fontları ~20 MB civarı. */
        private const val MAX_FONT_BYTES = 32L * 1024 * 1024
        private const val AVATAR_JPEG_QUALITY = 85

        /** bkz. `onChatWallpaperPicked` — avatardan daha büyük (tam ekran
         *  arka plan olarak gösterilecek), ama yine de makul bir üst sınır. */
        private const val WALLPAPER_MAX_DIMENSION = 1080
        private const val WALLPAPER_JPEG_QUALITY = 80

        /** Spec dışı, kullanıcı isteği: geçmiş/ek depolama sınırı slider'ı
         *  — 100MB'dan 32GB'a, ayrık adımlarla (Slider valueFrom=0..8). */
        private val HISTORY_STORAGE_LIMIT_STEPS_BYTES = longArrayOf(
            100L * 1024 * 1024,
            250L * 1024 * 1024,
            500L * 1024 * 1024,
            1L * 1024 * 1024 * 1024,
            2L * 1024 * 1024 * 1024,
            4L * 1024 * 1024 * 1024,
            8L * 1024 * 1024 * 1024,
            16L * 1024 * 1024 * 1024,
            32L * 1024 * 1024 * 1024
        )

        private fun formatStorageLimit(bytes: Long): String = when {
            bytes >= 1024L * 1024 * 1024 -> {
                val gb = bytes.toDouble() / (1024 * 1024 * 1024)
                if (gb == gb.toLong().toDouble()) "${gb.toLong()} GB" else "%.2f GB".format(gb)
            }
            else -> "${bytes / (1024 * 1024)} MB"
        }

        private fun closestStepIndex(bytes: Long): Int {
            var bestIndex = 0
            var bestDiff = Long.MAX_VALUE
            for (i in HISTORY_STORAGE_LIMIT_STEPS_BYTES.indices) {
                val diff = kotlin.math.abs(HISTORY_STORAGE_LIMIT_STEPS_BYTES[i] - bytes)
                if (diff < bestDiff) {
                    bestDiff = diff
                    bestIndex = i
                }
            }
            return bestIndex
        }

        /**
         * Spec dışı, hata düzeltmesi (gerçek cihaz çökmesi: "Value(1.24375)
         * must be equal to valueFrom(0.85) plus a multiple of stepSize(0.05)"):
         * metin/arayüz boyutu kaydırıcıları önceden ÇIPLAK bir ondalık
         * `stepSize` (0.05f) kullanıyordu — 0.05 ikili kayan noktada TAM
         * temsil edilemez, bu yüzden Material Slider'ın kendi iç
         * `validateValues()` kontrolü (her `onSizeChanged`'da çalışır),
         * SharedPreferences'tan geri okunan/tekrar atanan bir değerin
         * "valueFrom + N×stepSize" olup olmadığını doğrularken küçük bir
         * kayan nokta sapmasında bile `IllegalStateException` fırlatıp
         * uygulamayı ÇÖKERTİYORDU. Çözüm: `history_storage_limit_slider`
         * (bkz. yukarısı) ile AYNI desen — kaydırıcı SADECE TAM SAYI
         * indeksler üzerinde çalışır (`valueFrom=0, stepSize=1`, kayan
         * nokta hassasiyeti SÖZ KONUSU BİLE DEĞİL), gerçek ölçek değeri bu
         * sabit dizilerden indekslenir.
         */
        private val TEXT_SCALE_STEPS = floatArrayOf(
            0.70f, 0.75f, 0.80f, 0.85f, 0.90f, 0.95f, 1.00f, 1.05f, 1.10f, 1.15f,
            1.20f, 1.25f, 1.30f, 1.35f, 1.40f, 1.45f, 1.50f, 1.55f, 1.60f
        )
        private val UI_SCALE_STEPS = floatArrayOf(
            0.75f, 0.80f, 0.85f, 0.90f, 0.95f, 1.00f, 1.05f, 1.10f, 1.15f, 1.20f, 1.25f, 1.30f
        )

        private fun closestStepIndex(steps: FloatArray, value: Float): Int {
            var bestIndex = 0
            var bestDiff = Float.MAX_VALUE
            for (i in steps.indices) {
                val diff = kotlin.math.abs(steps[i] - value)
                if (diff < bestDiff) {
                    bestDiff = diff
                    bestIndex = i
                }
            }
            return bestIndex
        }
    }

    private lateinit var imgOwnAvatar: ImageView
    /** bkz. `imgOwnAvatar` tıklama dinleyicisi — tam ekran görüntüleyiciye
     *  taşınacak ham profil fotoğrafı baytları (bkz. AvatarUtil.openFullscreen). */
    private var ownAvatarBytes: ByteArray? = null
    private var displayNameValue: TextView? = null

    /** Spec dışı, kullanıcı isteği (Tor): durum etiketi + periyodik yoklama.
     *  Yoklama `onResume`da başlar, `onPause`'da BİTER: view yaratıldığı andan
     *  itibaren 2 sn'de bir çalışan bir JNI yoklaması, uygulama arka
     *  plandayken de sürüyordu (pilde ve çekirdek kilidinde gereksiz iş). */
    private var torStatusView: TextView? = null
    private val torStatusHandler = Handler(Looper.getMainLooper())
    private val torStatusRunnable = object : Runnable {
        override fun run() {
            updateTorStatusLabel()
            // Tor durumu (bootstrap) saniyeler içinde değişebildiğinden 2 sn'de
            // bir yenile.
            torStatusHandler.postDelayed(this, 2000)
        }
    }

    /** `registerForActivityResult` Fragment STARTED olmadan ÖNCE
     *  çağrılmalı — bkz. ChatActivity pickFileLauncher aynı notu. */
    private val pickAvatarLauncher = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        uri?.let { onAvatarPicked(it) }
    }

    /** bkz. `onChatWallpaperPicked` — `pickAvatarLauncher` ile AYNI desen. */
    private val pickWallpaperLauncher = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        uri?.let { onChatWallpaperPicked(it) }
    }

    /** bkz. font seçim diyalogu — `.ttf`/`.otf` font dosyası seçmek için;
     *  `pickWallpaperLauncher` ile AYNI `OpenDocument` deseni. */
    private val pickFontLauncher = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        uri?.let { onFontPicked(it) }
    }

    /**
     * Spec dışı, güvenlik denetimi düzeltmesi: Rust tarafı (`export_recovery`,
     * Argon2id ile sertleştirilmiş — bkz. SECURITY.md §6) daha önce hiçbir
     * ekrandan tetiklenemiyordu. Kullanıcının parolayı SAF (Storage Access
     * Framework, `CreateDocument`) ile seçtiği hedefe yazmadan HEMEN önce
     * `showExportRecoveryDialog`'da geçici olarak burada tutulur — bu dosya
     * TÜM uzun-vadeli kimlik anahtarlarını taşıdığından, hedef kullanıcının
     * KENDİSİNİN seçtiği bir konum olmalı (WRITE_EXTERNAL_STORAGE izni
     * gerektirmeyen, herhangi bir API seviyesinde tekdüze çalışan tek yol).
     */
    private var pendingRecoveryPassphrase: String? = null

    private val createRecoveryFileLauncher = registerForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        val passphrase = pendingRecoveryPassphrase
        pendingRecoveryPassphrase = null
        if (uri == null) return@registerForActivityResult
        if (passphrase == null) {
            // The fragment was recreated while the picker was open (rotation,
            // process death) and the passphrase is gone. The picker already
            // created the file: remove it, or an empty file stays behind as
            // the user's "recovery file".
            try {
                android.provider.DocumentsContract.deleteDocument(requireContext().contentResolver, uri)
            } catch (e: Exception) {
            }
            Toast.makeText(requireContext(), R.string.error_recovery_export_failed, Toast.LENGTH_LONG).show()
            return@registerForActivityResult
        }
        exportRecoveryTo(uri, passphrase)
    }

    /** Set while a server switch is put back after a failed change. */
    private var revertingServerToggle = false

    /** Runs a core server setting; on failure shows it and puts the switch
     *  back, so it never shows ON while nothing is stored or routed. */
    private fun applyServerToggle(switch: android.widget.CompoundButton, checked: Boolean, change: () -> String) {
        if (revertingServerToggle) return
        // H56: the core call (key creation, DB) must not run on the main thread.
        lifecycleScope.launch(Dispatchers.IO) {
            val result = try { change() } catch (e: Exception) { "Error: ${e.message}" }
            if (!result.startsWith("Error")) return@launch
            withContext(Dispatchers.Main) {
                Toast.makeText(switch.context, com.p2p.messenger.util.coreErrorText(switch.context, result), Toast.LENGTH_LONG).show()
                revertingServerToggle = true
                switch.isChecked = !checked
                revertingServerToggle = false
            }
        }
    }

    /** Each card's header folds/unfolds its body; the chevron shows the state. */
    private fun setupSections(root: View) {
        val sections = mapOf(
            "profile" to (R.id.section_profile_header to R.id.section_profile_body),
            "appearance" to (R.id.section_appearance_header to R.id.section_appearance_body),
            "privacy" to (R.id.section_privacy_header to R.id.section_privacy_body),
            "network" to (R.id.section_network_header to R.id.section_network_body),
            "servers" to (R.id.section_servers_header to R.id.section_servers_body),
            "devices" to (R.id.section_devices_header to R.id.section_devices_body),
            "account" to (R.id.section_account_header to R.id.section_account_body),
        )
        for ((key, ids) in sections) {
            val header = root.findViewById<TextView>(ids.first)
            val body = root.findViewById<View>(ids.second)
            // Chevron points down when folded, up when open (level 0 / 10000).
            val chevron = android.graphics.drawable.RotateDrawable().apply {
                drawable = header.compoundDrawablesRelative[2]
                fromDegrees = 0f; toDegrees = 180f
            }
            header.setCompoundDrawablesRelativeWithIntrinsicBounds(null, null, chevron, null)
            fun render() {
                val open = key in expandedSections
                body.visibility = if (open) View.VISIBLE else View.GONE
                chevron.level = if (open) 10000 else 0
            }
            render()
            header.setOnClickListener {
                if (!expandedSections.remove(key)) expandedSections.add(key)
                render()
            }
        }
    }

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View? {
        val view = inflater.inflate(R.layout.fragment_settings, container, false)

        imgOwnAvatar = view.findViewById(R.id.img_own_avatar)
        refreshOwnAvatar()
        // Spec dışı, kullanıcı isteği: profil fotoğrafına dokununca tam
        // ekran + pinch-to-zoom açar (bkz. AvatarUtil.openFullscreen).
        imgOwnAvatar.setOnClickListener { AvatarUtil.openFullscreen(requireContext(), ownAvatarBytes) }
        view.findViewById<Button>(R.id.btn_change_picture).setOnClickListener {
            AppLock.beginTrustedExcursion()
            pickAvatarLauncher.launch(arrayOf("image/*"))
        }
        view.findViewById<Button>(R.id.btn_remove_picture).setOnClickListener {
            setOwnAvatar(null)
        }

        // Kullanıcı isteği (2026-09-04): hesap adı — bkz.
        // `showChangeDisplayNameDialog`.
        displayNameValue = view.findViewById(R.id.display_name_value)
        refreshDisplayName()
        view.findViewById<Button>(R.id.btn_change_display_name).setOnClickListener {
            showChangeDisplayNameDialog()
        }

        val identityCodeValue = view.findViewById<android.widget.TextView>(R.id.identity_code_value)
        // fixpass (glm A3): JNI çağrısı (`getIdentityCode` → çekirdek kilidi)
        // ana iş parçacığından ÇALIŞMAZ; sonuç ana iş parçacığına yazılır.
        identityCodeValue.text = ""
        lifecycleScope.launch(Dispatchers.IO) {
            val code = try { P2PLib.getIdentityCode() } catch (e: Exception) { "" }
            withContext(Dispatchers.Main) {
                if (identityCodeValue.isAttachedToWindow) identityCodeValue.text = code
            }
        }

        val nodeModeSwitch = view.findViewById<SwitchMaterial>(R.id.node_mode_switch)
        nodeModeSwitch.isChecked = P2PService.isNodeModeEnabled(requireContext())

        val historyStorageLimitLabel = view.findViewById<TextView>(R.id.history_storage_limit_label)
        val historyStorageLimitDesc = view.findViewById<TextView>(R.id.history_storage_limit_desc)
        val historyStorageLimitValue = view.findViewById<TextView>(R.id.history_storage_limit_value)
        val historyStorageLimitSlider = view.findViewById<android.widget.SeekBar>(R.id.history_storage_limit_slider)

        fun setHistoryStorageLimitVisible(visible: Boolean) {
            val v = if (visible) View.VISIBLE else View.GONE
            historyStorageLimitLabel.visibility = v
            historyStorageLimitDesc.visibility = v
            historyStorageLimitValue.visibility = v
            historyStorageLimitSlider.visibility = v
        }

        val currentLimitBytes = P2PService.getHistoryStorageLimitBytes(requireContext())
        historyStorageLimitSlider.max = HISTORY_STORAGE_LIMIT_STEPS_BYTES.size - 1
        historyStorageLimitSlider.progress = closestStepIndex(currentLimitBytes)
        historyStorageLimitValue.text = formatStorageLimit(HISTORY_STORAGE_LIMIT_STEPS_BYTES[closestStepIndex(currentLimitBytes)])
        setHistoryStorageLimitVisible(nodeModeSwitch.isChecked)
        historyStorageLimitSlider.setOnSeekBarChangeListener(object : android.widget.SeekBar.OnSeekBarChangeListener {
            override fun onProgressChanged(bar: android.widget.SeekBar, progress: Int, fromUser: Boolean) {
                val bytes = HISTORY_STORAGE_LIMIT_STEPS_BYTES[progress]
                historyStorageLimitValue.text = formatStorageLimit(bytes)
                if (fromUser) {
                    P2PService.setHistoryStorageLimitBytes(requireContext(), bytes)
                }
            }
            override fun onStartTrackingTouch(bar: android.widget.SeekBar) {}
            override fun onStopTrackingTouch(bar: android.widget.SeekBar) {}
        })

        nodeModeSwitch.setOnCheckedChangeListener { _, isChecked ->
            P2PService.setNodeModeEnabled(requireContext(), isChecked)
            setHistoryStorageLimitVisible(isChecked)
        }

        // Spec dışı, kullanıcı isteği: Tor onion service — CGNAT arkasında da
        // ulaşılabilirlik (bkz. tor.rs / SECURITY.md). Node modunun aksine
        // CANLI toggle YOK: değişiklik ancak ağ katmanı yeniden başlayınca
        // etkinleşir (transport ancak startNetwork'te eklenebiliyor), bu yüzden
        // kullanıcıya "uygulamayı yeniden başlatın" uyarısı gösterilir.
        val torSwitch = view.findViewById<SwitchMaterial>(R.id.tor_switch)
        torStatusView = view.findViewById(R.id.tor_status)
        torSwitch.isChecked = P2PService.isTorEnabled(requireContext())
        torSwitch.setOnCheckedChangeListener { _, isChecked ->
            P2PService.setTorEnabled(requireContext(), isChecked)
            Toast.makeText(requireContext(), R.string.tor_restart_needed, Toast.LENGTH_LONG).show()
            if (!isChecked) Toast.makeText(requireContext(), R.string.tor_off_no_network, Toast.LENGTH_LONG).show()
        }
        // Yoklama `onResume`'da başlar (aşağıda) — view yaratılırken değil:
        // uygulama arka plandayken de sürmesin.

        // Spec dışı, güvenlik denetimi devamı: bkz. SECURITY.md
        // "Cross-network connectivity" notu — organik olarak keşfedilen bir
        // röle yoksa (ör. hiç Node modu açık, erişilebilir bir kişiyle
        // karşılaşılmadıysa), farklı ağlardaki iki kişinin ilk eşleşmesi
        // için tek garanti bu manuel adres.
        val relayAddressInput = view.findViewById<EditText>(R.id.relay_address_input)
        view.findViewById<Button>(R.id.btn_add_relay_address).setOnClickListener {
            val addr = relayAddressInput.text.toString().trim()
            if (addr.isEmpty()) return@setOnClickListener
            val result = try {
                P2PLib.addKnownRelayAddress(addr)
            } catch (e: Exception) {
                "Error: ${e.message}"
            }
            if (result.startsWith("Error:")) {
                Toast.makeText(requireContext(), com.p2p.messenger.util.coreErrorText(requireContext(), result), Toast.LENGTH_SHORT).show()
            } else {
                relayAddressInput.text.clear()
                Toast.makeText(requireContext(), R.string.msg_relay_address_added, Toast.LENGTH_SHORT).show()
            }
        }

        setupServers(view)

        setupAppearanceControls(view)
        setupLanguageControl(view)
        setupChatAppearanceControls(view)
        setupNotificationControls(view)
        setupAppLockControls(view)

        // Anahtarların donanım güvenlik modülünde (StrongBox/TEE) tutulup
        // tutulmadığını göster — kullanıcıya somut bir güvenlik göstergesi.
        val securityStatus = view.findViewById<android.widget.TextView>(R.id.key_security_status)
        securityStatus.text = if (com.p2p.messenger.util.KeystoreCrypto.isHardwareBacked()) {
            getString(R.string.lbl_keys_hardware_backed)
        } else {
            getString(R.string.lbl_keys_software_backed)
        }

        // bkz. `pendingRecoveryPassphrase`/`createRecoveryFileLauncher`
        // dokümantasyonu — daha önce hiçbir ekranda erişilemeyen kurtarma
        // dosyası dışa aktarma akışının tetiği.
        view.findViewById<Button>(R.id.btn_export_recovery).setOnClickListener {
            withAppPassword { showExportRecoveryDialog() }
        }

        // Spec dışı, kullanıcı isteği: bekleyen (henüz ack alınmamış)
        // mesajlar listesi — bkz. ui.PendingMessagesActivity.
        view.findViewById<Button>(R.id.btn_pending_messages).setOnClickListener {
            startActivity(Intent(requireContext(), PendingMessagesActivity::class.java))
        }

        view.findViewById<Button>(R.id.btn_storage).setOnClickListener {
            startActivity(Intent(requireContext(), StorageActivity::class.java))
        }

        // Çoklu-cihaz (spec 1.5): bağlı cihazları yönet / yeni cihaz ekle.
        view.findViewById<Button>(R.id.btn_linked_devices).setOnClickListener {
            showLinkedDevicesDialog()
        }

        // Spec dışı, kullanıcı isteği: hesaptan çıkış — bkz. `confirmLogout`.
        view.findViewById<Button>(R.id.btn_logout).setOnClickListener {
            withAppPassword { confirmLogout() }
        }
        view.findViewById<Button>(R.id.btn_delete_account).setOnClickListener {
            withAppPassword { confirmDeleteAccount() }
        }

        setupSections(view)
        return view
    }

    /**
     * Spec dışı, kullanıcı isteği: kullanıcı gerçek bir cihazda "İkincil
     * cihaz olarak bağlan" akışında (`LinkDeviceActivity`) bir çökme
     * yaşadı — çökme ANINDAN önce kimlik zaten diske yazılmıştı
     * (`createIdentityAndStart` -> `IdentityManager.persistNewIdentity`
     * `startActivity`'den ÖNCE çalışır), bu yüzden bir sonraki açılışta
     * `MainActivity.onCreate` `hasStoredIdentity()==true` görüp bu yarım
     * kalmış/eşleşmemiş kimlikle normal (yalnız) bir hesap gibi devam
     * ediyordu — kullanıcının baştan başlamasının hiçbir yolu yoktu. Bu,
     * o kilitlenmeden çıkış için genel bir "çıkış yap" kapısı: yerel
     * kimlik/mesaj/kişi verisini SİLER (bkz. `performLogout`) ve
     * `AppRestarter` ile temiz bir süreçte yeniden başlatır — bu da
     * `MainActivity`'yi `hasStoredIdentity()==false` görüp yeniden
     * `showDeviceNameDialog()`'a düşürür.
     */
    private fun confirmLogout() {
        AlertDialog.Builder(requireContext())
            .setTitle(R.string.logout_confirm_title)
            .setMessage(R.string.logout_confirm_message)
            .setPositiveButton(R.string.action_logout_confirm) { _, _ -> performLogout() }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    /**
     * Bu cihazdaki TÜM kalıcı kimlik/mesaj verisini siler: SQLite DB
     * (+ WAL/SHM yardımcı dosyaları), şifreli secret key bundle'ı
     * (`identity_secret.enc`), Keystore ile sarılmış DİĞER kimlik
     * anahtarları (geçmiş/skipped-key/ARK — bkz. [com.p2p.messenger.util.LocalWipe],
     * bu üçü burada ATLANIYORDU) ve ek (attachment) depolama dizini. Rust
     * çekirdeği bunları süreç İÇİNDE güvenle "unutacak" doğrulanmış bir
     * yola sahip değil (bkz. `AppRestarter` dokümantasyonu — AYNI gerekçe:
     * canlı bir süreçte kimlik/ağ durumunu sıfırlamak yerine dosyaları
     * silip TEMİZ bir süreçte yeniden başlamak). Görünüm/tema tercihleri
     * (`ThemePrefs`) kasıtlı olarak dokunulmadan bırakılır — kimliğe değil
     * cihaza ait, silinmeleri kullanıcı için bir kazanç sağlamaz.
     */
    /** Hesabı siler: önce tüm kişilere/gruplara/kardeş cihazlara bildirim
     *  gider (bkz. Rust `delete_account`), onaylar ya da en fazla
     *  [ACCOUNT_DELETE_WAIT_MS] beklenir (çevrimdışı kişilere sunucu üzerinden
     *  bırakılır), sonra `performLogout` ile yerel veri silinir. */
    /** This device is the root of the account (its fingerprint is the identity id). */
    private fun isRootDevice(): Boolean = try {
        val arr = org.json.JSONArray(P2PLib.listLinkedDevices())
        (0 until arr.length()).map { arr.getJSONObject(it) }
            .any { it.optBoolean("is_this_device") && it.optString("device_fingerprint") == P2PLib.getOwnIdentityId() }
    } catch (e: Exception) { true }

    private fun confirmDeleteAccount() {
        // fixpass (glm A3): `isRootDevice()` iki JNI çağrısı yapar — ana iş
        // parçacığından ÇALIŞMAZ; iletişim kutusu sonuç ana iş parçacığında
        // açılır.
        lifecycleScope.launch(Dispatchers.IO) {
            val root = isRootDevice()
            withContext(Dispatchers.Main) {
                // The core refuses it on a linked device; the generic "couldn't
                // notify your contacts" was shown for that.
                if (!root) {
                    Toast.makeText(requireContext(), R.string.msg_primary_device_only_delete, Toast.LENGTH_LONG).show()
                    return@withContext
                }
                AlertDialog.Builder(requireContext())
                    .setTitle(R.string.delete_account_confirm_title)
                    .setMessage(R.string.delete_account_confirm_message)
                    .setPositiveButton(R.string.action_delete_account) { _, _ -> performDeleteAccount() }
                    .setNegativeButton(android.R.string.cancel, null)
                    .show()
            }
        }
    }

    private fun performDeleteAccount() {
        val ctx = requireContext().applicationContext
        val progress = AlertDialog.Builder(requireContext())
            .setMessage(R.string.msg_deleting_account)
            .setCancelable(false)
            .show()
        Thread {
            // -1 or an exception: nothing was announced. Wiping now would
            // destroy the only keys that can ever announce it, and contacts,
            // groups and sibling devices would never learn of the deletion.
            val announced = try {
                val sent = P2PLib.deleteAccount()
                val deadline = android.os.SystemClock.elapsedRealtime() + ACCOUNT_DELETE_WAIT_MS
                while (sent >= 0 && android.os.SystemClock.elapsedRealtime() < deadline) {
                    if (P2PLib.accountDeletionPending() == 0) break
                    Thread.sleep(500)
                }
                sent >= 0
            } catch (e: Exception) {
                false
            }
            if (announced) com.p2p.messenger.util.LocalWipe.wipe(ctx)
            android.os.Handler(android.os.Looper.getMainLooper()).post {
                try { progress.dismiss() } catch (e: Exception) {}
                if (!announced) {
                    Toast.makeText(ctx, R.string.error_delete_account_failed, Toast.LENGTH_LONG).show()
                    return@post
                }
                AppRestarter.restart(ctx)
            }
        }.start()
    }

    private fun performLogout() {
        // Disk I/O off the UI thread (H144); the restart hops back to main.
        val app = requireContext().applicationContext
        Thread {
            com.p2p.messenger.util.LocalWipe.wipe(app)
            android.os.Handler(android.os.Looper.getMainLooper()).post { AppRestarter.restart(app) }
        }.start()
    }

    /**
     * Çoklu-cihaz (spec 1.5/1.6): kimliğe bağlı cihazları listeler, yeni bir
     * cihaz eklemeye (QR tarayarak) ve bir kardeş cihazı iptal etmeye izin
     * verir. "Cihaz ekle" akışı: DİĞER (yeni) cihazda "İkincil cihaz olarak
     * bağlan" seçilip bir QR gösterilir; BU (var olan) cihaz o QR'ı tarar.
     */
    private fun showLinkedDevicesDialog() {
        val json = try { P2PLib.listLinkedDevices() } catch (e: Exception) { "[]" }
        val arr = try { org.json.JSONArray(json) } catch (e: Exception) { org.json.JSONArray() }
        val labels = ArrayList<String>()
        val fingerprints = ArrayList<String?>()
        val revokedFps = ArrayList<String?>()
        val thisDevice = getString(R.string.linked_devices_this_device)
        for (i in 0 until arr.length()) {
            val o = arr.getJSONObject(i)
            val name = o.optString("device_name").ifEmpty { o.optString("device_fingerprint").take(8) }
            val isThis = o.optBoolean("is_this_device", false)
            val isActive = o.optBoolean("is_active", true)
            val suffix = when {
                isThis -> " ($thisDevice)"
                !isActive -> " (${getString(R.string.linked_devices_revoked)})"
                else -> ""
            }
            labels.add(name + suffix)
            fingerprints.add(if (isThis || !isActive) null else o.optString("device_fingerprint"))
            revokedFps.add(if (!isThis && !isActive) o.optString("device_fingerprint") else null)
        }

        AlertDialog.Builder(requireContext())
            .setTitle(R.string.linked_devices_section_title)
            .setItems(labels.toTypedArray()) { _, which ->
                val fp = fingerprints.getOrNull(which)
                if (fp != null) withAppPassword { confirmRevokeLinkedDevice(fp) }
                revokedFps.getOrNull(which)?.let { confirmForgetRevokedDevice(it) }
            }
            .setPositiveButton(R.string.linked_devices_add) { _, _ ->
                // Only the root device may add one (the core refuses the grant):
                // say so before the camera opens, not after a scan.
                // fixpass (glm A3): `isRootDevice()` JNI — off the main thread.
                lifecycleScope.launch(Dispatchers.IO) {
                    val root = isRootDevice()
                    withContext(Dispatchers.Main) {
                        if (!isAdded) return@withContext
                        if (!root) {
                            Toast.makeText(requireContext(), R.string.msg_primary_device_only, Toast.LENGTH_LONG).show()
                            return@withContext
                        }
                        withAppPassword {
                            startActivity(
                                Intent(requireContext(), com.p2p.messenger.ui.QrScanActivity::class.java).apply {
                                    putExtra(com.p2p.messenger.ui.QrScanActivity.EXTRA_MODE,
                                        com.p2p.messenger.ui.QrScanActivity.MODE_LINK_APPROVE)
                                }
                            )
                        }
                    }
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    /** Asks for the app password before [action]: whoever holds the unlocked
     *  phone is not always its owner. */
    private fun withAppPassword(action: () -> Unit) {
        val context = requireContext()
        if (!AppLock.hasPassword(context)) {
            action()
            return
        }
        val wait = AppLock.retryWaitSeconds(context)
        if (wait > 0) {
            Toast.makeText(context, getString(R.string.error_app_lock_wait, wait), Toast.LENGTH_LONG).show()
            return
        }
        val field = EditText(context).apply {
            hint = getString(R.string.hint_app_lock_current)
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        }
        val container = LinearLayout(context).apply {
            val pad = (20 * resources.displayMetrics.density).toInt()
            setPadding(pad, pad / 2, pad, 0)
            addView(field)
        }
        AlertDialog.Builder(context)
            .setTitle(R.string.title_app_lock_unlock)
            .setView(container)
            .setPositiveButton(android.R.string.ok) { _, _ ->
                val entered = field.text.toString()
                lifecycleScope.launch(Dispatchers.IO) {
                    val ok = AppLock.verify(context, entered)
                    if (ok) AppLock.clearFailedAttempts(context) else AppLock.noteFailedAttempt(context)
                    withContext(Dispatchers.Main) {
                        if (!ok) {
                            Toast.makeText(context, R.string.error_app_lock_wrong, Toast.LENGTH_LONG).show()
                        } else if (isAdded) {
                            action()
                        }
                    }
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    /** A revoked device only clutters the list; the core keeps its record
     *  and the revoke (it is told again if it ever writes), so no password. */
    private fun confirmForgetRevokedDevice(fingerprint: String) {
        AlertDialog.Builder(requireContext())
            .setMessage(R.string.linked_devices_confirm_forget)
            .setPositiveButton(R.string.action_remove_from_list) { _, _ ->
                val ctx = requireContext().applicationContext
                lifecycleScope.launch(Dispatchers.IO) {
                    val result = try { P2PLib.forgetRevokedLinkedDevice(fingerprint) } catch (e: Exception) { "Error: ${e.message}" }
                    withContext(Dispatchers.Main) {
                        if (result.startsWith("Error:")) {
                            Toast.makeText(ctx, com.p2p.messenger.util.coreErrorText(ctx, result), Toast.LENGTH_SHORT).show()
                        } else if (isAdded) {
                            showLinkedDevicesDialog()
                        }
                    }
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun confirmRevokeLinkedDevice(fingerprint: String) {
        AlertDialog.Builder(requireContext())
            .setMessage(R.string.linked_devices_confirm_revoke)
            .setPositiveButton(R.string.action_revoke_device) { _, _ ->
                // Signs and fans the revocation out to every contact and
                // sibling under the core lock: not on the main thread.
                val ctx = requireContext().applicationContext
                lifecycleScope.launch(Dispatchers.IO) {
                    val result = try { P2PLib.revokeLinkedDevice(fingerprint) } catch (e: Exception) { "Error: ${e.message}" }
                    withContext(Dispatchers.Main) {
                        Toast.makeText(ctx,
                            if (result.startsWith("Error:")) com.p2p.messenger.util.coreErrorText(ctx, result) else ctx.getString(R.string.msg_device_revoked),
                            Toast.LENGTH_SHORT).show()
                    }
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    /**
     * Spec dışı, kullanıcı isteği: metin boyutu/arayüz boyutu kaydırıcıları
     * + sistem fontu seçici — bkz. `ThemePrefs`/`P2PApplication.applyScalePreferences`
     * (her ikisi de `onActivityPreCreated`'da, Activity daha `onCreate`
     * ÇALIŞMADAN önce uygulanır). OLED anahtarıyla AYNI sebep: değişiklik
     * ancak bir sonraki Activity oluşturmasında etkinleşir, bu yüzden HER
     * ÜÇÜ de değer serbest bırakıldığında (kaydırıcı) / seçildiğinde
     * (dropdown) `requireActivity().recreate()` çağırır — kaydırma
     * SIRASINDA değil (aksi hâlde saniyede onlarca gereksiz recreate
     * olurdu), sadece SONUÇ değerinde.
     */
    private fun setupAppearanceControls(view: View) {
        val textScaleValue = view.findViewById<TextView>(R.id.text_scale_value)
        val textScaleSlider = view.findViewById<android.widget.SeekBar>(R.id.text_scale_slider)
        // bkz. `TEXT_SCALE_STEPS`/`closestStepIndex` dokümantasyonu — TAM
        // SAYI indeks (kayan nokta `stepSize` DEĞİL), gerçek Material
        // Slider çökmesini (bkz. o notun ayrıntısı) kökünden önler.
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

        // bkz. ThemePrefs.FontChoice — sırası buradaki görünen isim listesiyle
        // BİREBİR eşleşmeli (index bazlı eşleme). `CUSTOM` bu listede YOK —
        // bir dizin değil, `ThemePrefs.getCustomFonts()`'taki N içe aktarılmış
        // fonttan HANGİSİNİN seçili olduğunu `getActiveCustomFontId` ayrıca
        // tutuyor (bkz. aşağıdaki diyalog kurulumu — kullanıcı isteği:
        // "custom" yerine içe aktarılan fontun GERÇEK adı, birden fazla
        // içe aktarma desteklenmeli).
        val fontChoices = ThemePrefs.FontChoice.entries.filter { it != ThemePrefs.FontChoice.CUSTOM }
        val fontLabels = arrayOf(
            getString(R.string.lbl_font_default),
            getString(R.string.lbl_font_sans_medium),
            getString(R.string.lbl_font_sans_condensed),
            getString(R.string.lbl_font_serif),
            getString(R.string.lbl_font_monospace),
            getString(R.string.lbl_font_sans_black)
        )
        // Spec dışı, hata düzeltmesi (ikinci deneme — "comboboxta hâlâ
        // sadece Default görünüyor"): `MaterialAutoCompleteTextView` +
        // `setSimpleItems` teoride filtrelenmemesi GEREKEN bir liste
        // vermeliydi, ama kullanıcı gerçek cihazda hâlâ tek seçenek
        // gördüğünü bildirdi — bu View'ın (exposed dropdown popup'ının
        // açılma/gösterim mantığı) bu ortamda hiç test edilemediğinden,
        // TAMAMEN farklı ve kırılması çok daha zor bir mekanizmaya
        // geçiliyor: düz bir `Button` + `AlertDialog.setSingleChoiceItems`.
        // Bu, listeleme/filtreleme gibi hiçbir "akıllı" davranışa sahip
        // değil — TÜM seçenekler HER ZAMAN gösterilir.
        //
        // BİLİNEN SINIR: bu liste sadece Android'in HER cihazda var olması
        // GARANTİ jenerik takma adlarını (`sans-serif`, `serif`,
        // `monospace` + ağırlık/genişlik varyantları) sunar — cihaz
        // üreticisinin (ör. Samsung/Xiaomi) Ayarlar'da gösterdiği MARKALI/
        // İNDİRİLMİŞ font adlarını (ör. "One UI Sans", indirilen bir Google
        // Fonts ailesi) numaralandırıp listelemenin genel, resmi bir
        // Android API'si YOK — bu yüzden burada asla görünmeyecekler.
        // "Varsayılan" seçeneği yine de cihazın O ANKİ sistem varsayılanını
        // (kullanıcı üretici ayarlarından değiştirmiş olsa BİLE) kullanır,
        // çünkü hiçbir override UYGULAMAZ.
        val fontValueText = view.findViewById<TextView>(R.id.font_family_value)
        fun currentFontLabel(): String {
            val choice = ThemePrefs.getFontChoice(requireContext())
            return if (choice == ThemePrefs.FontChoice.CUSTOM) {
                // bkz. `ThemePrefs.activeCustomFontName` — birden fazla içe
                // aktarılmış font arasından seçili olanın GERÇEK adı; kayıt
                // bozulmuşsa (id silinmiş) jenerik ada düşülür.
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
            // Diyalog satırları: [0] "İçe aktar", [1..fontChoices.size] yerleşik
            // fontlar, gerisi (varsa) içe aktarılmış fontlar — HER BİRİ kendi
            // adıyla (bkz. `ThemePrefs.CustomFont.displayName`, kullanıcı
            // isteği: "custom" değil gerçek font adı, birden fazla olabilmeli).
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
                            // "Import a .ttf file…" — font seçmez, dialog'u
                            // kapatıp dosya seçiciyi açar.
                            dialog.dismiss()
                            AppLock.beginTrustedExcursion()
                            pickFontLauncher.launch(arrayOf("font/ttf", "font/otf", "application/x-font-ttf", "application/octet-stream", "*/*"))
                        }
                        position <= fontChoices.size -> {
                            // bkz. `fontChoices` — position 1+ → index = position - 1
                            val chosen = fontChoices[position - 1]
                            if (chosen != currentChoice) {
                                ThemePrefs.setFontChoice(requireContext(), chosen)
                                fontValueText.text = fontLabels[position - 1]
                                // Spec dışı, kullanıcı isteği ("force font on all UI"):
                                // bkz. `FontOverride` dokümantasyonu — Android'in
                                // varsayılan Typeface'ini HEMEN değiştirir
                                // (P2PApplication.onCreate sadece SÜREÇ başlangıcında
                                // çalışır, bu çağrı olmadan değişiklik ancak bir
                                // sonraki tam uygulama yeniden başlatmasında
                                // görülürdü). `recreate()` bunun ardından bu
                                // Activity'yi hemen yeniden çizer, ARTIK güncellenmiş
                                // varsayılan Typeface'le.
                                com.p2p.messenger.util.FontOverride.apply(chosen.familyName)
                                requireActivity().recreate()
                            }
                            dialog.dismiss()
                        }
                        else -> {
                            // Daha önce içe aktarılmış fontlardan biri seçildi
                            // (bkz. `dialogLabels` — bu satırlar `customFonts`'a
                            // fontChoices.size kadar kaydırılmış eşleşir).
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

    /**
     * Spec dışı, kullanıcı isteği: "bildirimlerde mesajları göster"
     * anahtarı — varsayılan AÇIK. Kapalıyken bildirimde sadece gönderen
     * (grup mesajıysa gönderen + grup) görünür, metin görünmez. bkz.
     * util.NotificationPrefs / NotificationHelper.
     */
    private fun setupNotificationControls(view: View) {
        val notifSwitch = view.findViewById<SwitchMaterial>(R.id.notif_show_message_switch)
        notifSwitch.isChecked = NotificationPrefs.showMessageText(requireContext())
        notifSwitch.setOnCheckedChangeListener { _, checked ->
            NotificationPrefs.setShowMessageText(requireContext(), checked)
        }
    }

    /**
     * Spec dışı, kullanıcı isteği: uygulama açılış şifresi — buradan
     * yalnızca DEĞİŞTİRİLEBİLİR. Kaldırma seçeneği BİLEREK yok ("şifre asla
     * boş olmamalı"); boş bir yeni şifre de kabul edilmez.
     *
     * Mevcut şifre doğrulaması `AppLock.verify` ile yapılıyor — kilitli
     * olmayan bir oturumda (kullanıcı zaten içeride) telefonu kısa süre
     * eline geçiren birinin şifreyi sessizce değiştirmesini engeller.
     * `AppLock.verify`/`setPassword` kasıtlı olarak yavaş bir KDF çalıştırır
     * (bkz. AppLock.ITERATIONS), bu yüzden ana thread DIŞINDA çağrılıyor.
     */
    private fun setupAppLockControls(view: View) {
        view.findViewById<Button>(R.id.btn_change_app_password).setOnClickListener {
            val context = requireContext()
            val container = LinearLayout(context).apply {
                orientation = LinearLayout.VERTICAL
                val pad = (20 * resources.displayMetrics.density).toInt()
                setPadding(pad, pad / 2, pad, 0)
            }
            fun passwordField(hintRes: Int) = EditText(context).apply {
                hint = getString(hintRes)
                inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            }
            // Şifre henüz hiç kurulmamışsa (ör. bu sürüme yükseltilmiş eski
            // bir kurulum, kilit ekranını henüz görmemiş) "mevcut şifre"
            // alanını sormanın anlamı yok.
            val hasExisting = AppLock.hasPassword(context)
            val currentField = passwordField(R.string.hint_app_lock_current)
            val newField = passwordField(R.string.hint_app_lock_new)
            val confirmField = passwordField(R.string.hint_app_lock_password_confirm)
            if (hasExisting) container.addView(currentField)
            container.addView(newField)
            container.addView(confirmField)

            AlertDialog.Builder(context)
                .setTitle(R.string.action_change_app_password)
                .setView(container)
                .setPositiveButton(R.string.action_app_lock_save) { _, _ ->
                    val newPassword = newField.text.toString()
                    if (newPassword.isBlank()) {
                        Toast.makeText(context, R.string.error_app_lock_empty, Toast.LENGTH_LONG).show()
                        return@setPositiveButton
                    }
                    if (newPassword.length < AppLock.MIN_PASSWORD_LENGTH) {
                        Toast.makeText(context, getString(R.string.error_app_lock_short, AppLock.MIN_PASSWORD_LENGTH), Toast.LENGTH_LONG).show()
                        return@setPositiveButton
                    }
                    if (newPassword != confirmField.text.toString()) {
                        Toast.makeText(context, R.string.error_app_lock_mismatch, Toast.LENGTH_LONG).show()
                        return@setPositiveButton
                    }
                    val current = currentField.text.toString()
                    lifecycleScope.launch(Dispatchers.IO) {
                        val waitSec = if (hasExisting) AppLock.retryWaitSeconds(context) else 0
                        val currentOk = !hasExisting || AppLock.verifyThrottled(context, current)
                        if (currentOk) AppLock.setPassword(context, newPassword)
                        withContext(Dispatchers.Main) {
                            if (waitSec > 0) {
                                Toast.makeText(context, getString(R.string.error_app_lock_wait, waitSec), Toast.LENGTH_LONG).show()
                                return@withContext
                            }
                            val messageRes = if (currentOk) {
                                R.string.msg_app_lock_changed
                            } else {
                                R.string.error_app_lock_wrong
                            }
                            Toast.makeText(context, messageRes, Toast.LENGTH_LONG).show()
                        }
                    }
                }
                .setNegativeButton(android.R.string.cancel, null)
                .show()
        }
    }

    /** Language picker (English/Turkish). AppCompatDelegate.setApplicationLocales
     *  persists the choice itself (see AndroidManifest AppLocalesMetadataHolderService)
     *  and recreates all activities; the explicit recreate() below matches this
     *  screen's own font/color pickers for immediate visual feedback. */
    private fun setupLanguageControl(view: View) {
        val languageCodes = arrayOf("en", "tr")
        val languageLabels = arrayOf("English", "Türkçe")
        val languageValueText = view.findViewById<TextView>(R.id.language_value)
        fun currentLanguageIndex(): Int {
            val current = AppCompatDelegate.getApplicationLocales().toLanguageTags()
            return languageCodes.indexOfFirst { current.startsWith(it) }.coerceAtLeast(0)
        }
        languageValueText.text = languageLabels[currentLanguageIndex()]
        view.findViewById<Button>(R.id.btn_pick_language).setOnClickListener {
            AlertDialog.Builder(requireContext())
                .setTitle(R.string.lbl_language)
                .setSingleChoiceItems(languageLabels, currentLanguageIndex()) { dialog, position ->
                    AppCompatDelegate.setApplicationLocales(LocaleListCompat.forLanguageTags(languageCodes[position]))
                    dialog.dismiss()
                    requireActivity().recreate()
                }
                .setNegativeButton(android.R.string.cancel, null)
                .show()
        }
    }

    private fun formatScalePercent(scale: Float): String = getString(R.string.lbl_scale_percent, (scale * 100).toInt())

    /**
     * Spec dışı, kullanıcı isteği: TEK bir vurgu (accent) rengi — HER YERDE
     * (düğmeler, anahtarlar, kaydırıcılar, KENDİ mesaj balonlarımız)
     * varyasyonlarıyla (bkz. `ThemePrefs.applyAccentColor` — Material'ın
     * content-based dynamic color motoru) kullanılır; metin rengi AYRICA
     * seçilmez, HER ZAMAN o rengin üzerinde okunaklı siyah/beyaz otomatik
     * hesaplanır. Arka plan rengi ise hem genel UI hem sohbet ekranı için
     * GEÇERLİ (bkz. `ThemePrefs.applyChatBackground`).
     * Renk seçici tam bir HSV seçici (bkz. `HsvColorPickerDialog`) — harici
     * bir kütüphane GEREKTİRMEZ (bu proje build'i bu ortamda
     * doğrulanamadığından yeni bir Gradle bağımlılığı eklemekten kaçınıyoruz).
     * Her iki renk de (accent VE background) tüm uygulamanın temasını
     * değiştirdiğinden — OLED/font gibi — seçim SONRASI `recreate()` gerekir.
     */
    private fun setupChatAppearanceControls(view: View) {
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
                wallpaperThumb.setImageBitmap(android.graphics.BitmapFactory.decodeFile(file.absolutePath))
                previewEffects()
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
                        android.util.Log.w("SettingsFragment", "wallpaper effects failed", e)
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
     * bkz. `onAvatarPicked` AYNI `content://` -> yerel dosya kopyalama
     * deseni. Profil fotoğrafından FARKI: bu SADECE yerel bir UI tercihi,
     * hiçbir kişiye gönderilmiyor (bkz. ThemePrefs.chatWallpaperFile) — bu
     * yüzden Rust'a hiç dokunmuyor.
     */
    private fun onChatWallpaperPicked(uri: Uri) {
        // Off the fragment: `requireContext()` on the worker threw once the
        // screen was gone.
        val app = requireContext().applicationContext
        lifecycleScope.launch(Dispatchers.IO) {
            val tempFile = File(File(app.cacheDir, "wallpaper").apply { mkdirs() }, UUID.randomUUID().toString())
            try {
                app.contentResolver.openInputStream(uri)?.use { input ->
                    tempFile.outputStream().use { output -> input.copyTo(output, bufferSize = 64 * 1024) }
                } ?: throw java.io.IOException("Dosya açılamadı")
                val compressed = ImagePreview.compressFile(tempFile, WALLPAPER_MAX_DIMENSION, WALLPAPER_JPEG_QUALITY)
                if (compressed != null) {
                    ThemePrefs.chatWallpaperFile(app).writeBytes(compressed)
                    // New image: rebuild the processed copy with the current slider values.
                    ThemePrefs.regenerateProcessedWallpaper(app)
                }
                withContext(Dispatchers.Main) {
                    view?.let { v ->
                        val thumb = v.findViewById<ImageView>(R.id.chat_wallpaper_thumb)
                        val btnRemove = v.findViewById<Button>(R.id.btn_remove_chat_wallpaper)
                        val file = ThemePrefs.chatWallpaperFile(app)
                        if (file.exists()) {
                            thumb.setImageBitmap(android.graphics.BitmapFactory.decodeFile(file.absolutePath))
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
     * bkz. `onChatWallpaperPicked` — `content://` URI'den yerel
     * `filesDir`'e HAM bayt kopyalama; saf (coroutines/thread) yok,
     * senkron, basit `openInputStream` → `copyTo`. Font dosyası küçük
     * olduğu için (genellikle <1 MB) blok boyutu optimizasyonuna gerek yok.
     *
     * Spec dışı, kullanıcı isteği ("custom değil o fontun adı, birden fazla
     * import edilebilmeli"): her seçim YENİ bir kimlikle (`newCustomFontId`)
     * kendi dosyasına kopyalanır ve listeye EKLENİR (önceki içe aktarılmış
     * fontlar KAYBOLMAZ) — görünen ad, SAF'ın verdiği GERÇEK dosya adı
     * (`OpenableColumns.DISPLAY_NAME`). Kopyalama BAŞARISIZ olursa (ya da
     * SAF ad vermezse ve kalan yol da başarısız olursa) hiçbir kayıt
     * eklenmez/seçilmez — yetim bir liste girdisi kalmaz.
     */
    private fun onFontPicked(uri: Uri) {
        // Copies up to 32 MB: off the main thread.
        val ctx = requireContext().applicationContext
        lifecycleScope.launch {
            val displayName = withContext(Dispatchers.IO) { copyPickedFont(ctx, uri) } ?: return@launch
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
    private fun copyPickedFont(context: android.content.Context, uri: Uri): Pair<String, String>? {
        val id = ThemePrefs.newCustomFontId()
        val file = ThemePrefs.customFontFile(context, id)
        try {
            context.contentResolver.openInputStream(uri)?.use { input ->
                // "*/*" seçici her dosyayı kabul ediyor: yalnızca font imzası
                // (TrueType/OpenType/koleksiyon) olan ve makul boyuttaki
                // dosyalar kopyalanır — yanlışlıkla seçilen bir video
                // filesDir'i doldurmasın, bozuk dosya listeye girmesin.
                // `readNBytes` API 33+; minSdk 26 — kısa dosyada EOFException.
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
            // bkz. `onChatWallpaperPicked` — çökmemeli, sessizce geç; yarım
            // kalmış dosyayı da bırakma (listeye hiç eklenmediği için zaten
            // seçilemez, ama diskte yetim kalmasın).
            file.delete()
            return null
        }
    }

    /** SAF'ın verdiği `content://` URI'den GERÇEK dosya adını okur (bkz.
     *  `onFontPicked` — font listesinde "Custom" yerine bu ad gösterilir).
     *  Bazı sağlayıcılar bu sütunu doldurmayabilir; `null` dönerse çağıran
     *  taraf kendi dosya adına düşer. */
    private fun queryDisplayName(context: android.content.Context, uri: Uri): String? {
        return try {
            context.contentResolver.query(uri, arrayOf(android.provider.OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cursor ->
                val idx = cursor.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
                if (idx >= 0 && cursor.moveToFirst()) cursor.getString(idx) else null
            }
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Spec dışı, kullanıcı isteği: üst çubukta hızlı Tor/ağ bağlantısını
     * kes/yeniden kur menü öğesi — bkz. util/AppRestarter.kt (neden tam bir
     * uygulama yeniden başlatması gerektiği), menu_settings.xml. MainActivity
     * TEK bir Activity, üç bottom-nav sekmesi (Chats/Contacts/Settings)
     * paylaşıyor — `MenuProvider`, `viewLifecycleOwner` + `RESUMED` ile
     * kaydedildiğinden bu menü öğesi SADECE Ayarlar sekmesi görünürken
     * belirir, diğer sekmelerde otomatik kaybolur (Fragment view'ı
     * destroy olduğunda provider da kaldırılır — elle temizlemeye gerek
     * yok). `onCreateView` İÇİNDE değil `onViewCreated`'ta kaydedilir:
     * `viewLifecycleOwner`, fragment'ın view'ı `onCreateView`'dan DÖNENE
     * kadar geçerli değildir.
     */
    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        requireActivity().addMenuProvider(object : MenuProvider {
            override fun onCreateMenu(menu: Menu, menuInflater: MenuInflater) {
                menuInflater.inflate(R.menu.menu_settings, menu)
            }

            override fun onMenuItemSelected(menuItem: MenuItem): Boolean {
                if (menuItem.itemId == R.id.action_tor_reconnect) {
                    AppRestarter.confirmAndRestart(requireContext())
                    return true
                }
                return false
            }
        }, viewLifecycleOwner, Lifecycle.State.RESUMED)
    }

    /**
     * Spec dışı, güvenlik denetimi düzeltmesi: parolayı (+ onayını) alır,
     * eşleşmiyorsa/boşsa kullanıcıyı uyarır, eşleşiyorsa SAF hedef seçici
     * ile devam eder (bkz. `createRecoveryFileLauncher`). Rust tarafı
     * (`export_recovery`) parolayı Argon2id ile sertleştirdiğinden burada
     * herhangi bir minimum uzunluk/karmaşıklık kuralı DAYATMIYORUZ — kısa
     * bir parola daha ucuz brute-force edilir ama bu kullanıcının kendi
     * riski/tercihi, spec bunun ötesinde bir politika belirtmiyor.
     */
    private fun showExportRecoveryDialog() {
        val context = requireContext()
        val layout = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            val pad = (16 * resources.displayMetrics.density).toInt()
            setPadding(pad, pad, pad, pad)
        }
        val passwordInput = EditText(context).apply {
            hint = getString(R.string.lbl_recovery_password)
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        }
        val confirmInput = EditText(context).apply {
            hint = getString(R.string.lbl_recovery_password_confirm)
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        }
        layout.addView(passwordInput)
        layout.addView(confirmInput)

        AlertDialog.Builder(context)
            .setTitle(R.string.action_export_recovery)
            .setMessage(R.string.lbl_recovery_export_desc)
            .setView(layout)
            .setPositiveButton(R.string.action_export_recovery) { _, _ ->
                val password = passwordInput.text.toString()
                val confirm = confirmInput.text.toString()
                when {
                    password.isEmpty() -> Toast.makeText(context, R.string.error_recovery_password_empty, Toast.LENGTH_SHORT).show()
                    // Offline guessing is the only thing between this file and every key.
                    password.length < 12 -> Toast.makeText(context, getString(R.string.error_recovery_password_short, 12), Toast.LENGTH_LONG).show()
                    password != confirm -> Toast.makeText(context, R.string.error_recovery_password_mismatch, Toast.LENGTH_SHORT).show()
                    else -> {
                        pendingRecoveryPassphrase = password
                        val stamp = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date())
                        AppLock.beginTrustedExcursion()
                        createRecoveryFileLauncher.launch("typeon-recovery-$stamp.bin")
                    }
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    /**
     * `uri`'ye (kullanıcının SAF ile seçtiği hedef) Argon2id-şifreli kurtarma
     * dosyasını yazar. `P2PLib.exportRecovery` KASITLI OLARAK yavaş/bellek-
     * ağır bir KDF çalıştırdığından (bkz. Cargo.toml Argon2id notu) ANA
     * THREAD DIŞINDA çağrılır — aksi halde saniyeler süren bir ANR riski
     * olurdu. Boş bir bayt dizisi (bkz. Rust `Java_..._exportRecovery`
     * dokümantasyonu) başarısızlık anlamına gelir.
     */
    private fun exportRecoveryTo(uri: Uri, passphrase: String) {
        Toast.makeText(requireContext(), R.string.msg_recovery_exporting, Toast.LENGTH_SHORT).show()
        // Taken now: the export runs for seconds and `requireContext()` on the
        // worker threw once the user had left the screen meanwhile.
        val resolver = requireContext().applicationContext.contentResolver
        lifecycleScope.launch(Dispatchers.IO) {
            val bytes = try {
                P2PLib.exportRecovery(passphrase)
            } catch (e: Exception) {
                null
            }
            val ok = try {
                if (bytes != null && bytes.isNotEmpty()) {
                    resolver.openOutputStream(uri)?.use { out -> out.write(bytes); true } ?: false
                } else {
                    false
                }
            } catch (e: Exception) {
                false
            }
            withContext(Dispatchers.Main) {
                if (isAdded) {
                    Toast.makeText(
                        requireContext(),
                        if (ok) R.string.msg_recovery_export_success else R.string.error_recovery_export_failed,
                        Toast.LENGTH_LONG
                    ).show()
                }
            }
        }
    }

    private fun refreshDisplayName() {
        val name = try {
            P2PLib.getDisplayName()
        } catch (e: Exception) {
            ""
        }
        displayNameValue?.text = name
    }

    /**
     * Kullanıcı isteği (2026-09-04): hesap adını değiştirmek ve
     * değişikliğin kişilere OTOMATİK ulaşması.
     *
     * `setOwnAvatar` ile AYNI desen ve AYNI sebep: fan-out kişi başına
     * ayrı bir şifreleme yapıyor (bkz. Rust `set_display_name`), yani ana
     * thread'de çağrılamaz. Arayüzdeki ad hemen güncellenir — gönderim
     * arka planda, çevrimdışı kişiler için günlerce yeniden denenerek
     * sürer, kullanıcının bunu beklemesi gerekmez.
     */
    private fun showChangeDisplayNameDialog() {
        val current = try {
            P2PLib.getDisplayName()
        } catch (e: Exception) {
            ""
        }
        val input = EditText(requireContext()).apply {
            setText(current)
            setSingleLine(true)
            // Rust tarafı da kırpıyor (`MAX_DISPLAY_NAME_CHARS`); buradaki
            // sınır yalnızca kullanıcının sessizce kesilen bir ad
            // yazmasını engellemek için.
            filters = arrayOf(android.text.InputFilter.LengthFilter(48))
        }
        AlertDialog.Builder(requireContext())
            .setTitle(R.string.dlg_change_display_name_title)
            .setMessage(R.string.lbl_display_name_desc)
            .setView(input)
            .setPositiveButton(android.R.string.ok) { _, _ ->
                val name = input.text.toString().trim()
                if (name.isEmpty()) return@setPositiveButton
                displayNameValue?.text = name
                lifecycleScope.launch(Dispatchers.IO) {
                    val result = try {
                        P2PLib.setDisplayName(name)
                    } catch (e: Exception) {
                        "Error: ${e.message}"
                    }
                    withContext(Dispatchers.Main) {
                        if (!isAdded) return@withContext
                        if (result.startsWith("Error:")) {
                            Toast.makeText(requireContext(), com.p2p.messenger.util.coreErrorText(requireContext(), result), Toast.LENGTH_LONG).show()
                            refreshDisplayName()
                        } else {
                            Toast.makeText(requireContext(), R.string.msg_display_name_changed, Toast.LENGTH_SHORT).show()
                        }
                    }
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun refreshOwnAvatar() {
        val bytes = try {
            P2PLib.getOwnProfilePicture().takeIf { it.isNotEmpty() }
        } catch (e: Exception) {
            null
        }
        // Fotoğraf yoksa baş harf gösteriliyor (bkz. AvatarUtil) — hesap
        // adının baş harfi, kimlik kodunun ilk karakterinden ("a3f…")
        // anlamlı: kişiler bizi zaten o adla görüyor.
        val name = try {
            P2PLib.getDisplayName().ifEmpty { P2PLib.getIdentityShortCode() }
        } catch (e: Exception) {
            "?"
        }
        ownAvatarBytes = bytes
        AvatarUtil.renderInto(imgOwnAvatar, bytes, name)
    }

    /**
     * Kullanıcının SAF (`OpenDocument`) ile seçtiği bir görsel — bkz.
     * ChatActivity.onFilePicked aynı `content://` -> yerel dosya kopyalama
     * notu. 720p/%85 JPEG'e sıkıştırılıp `setOwnProfilePicture` ile hem
     * kalıcılaştırılır hem TÜM bilinen kişilere gönderilir (bkz. Rust
     * `set_own_profile_picture` dokümantasyonu) — bu yüzden ANA THREAD
     * DIŞINDA yapılır.
     */
    private fun onAvatarPicked(uri: Uri) {
        val app = requireContext().applicationContext
        lifecycleScope.launch(Dispatchers.IO) {
            val tempFile = File(File(app.cacheDir, "avatar").apply { mkdirs() }, UUID.randomUUID().toString())
            try {
                app.contentResolver.openInputStream(uri)?.use { input ->
                    tempFile.outputStream().use { output -> input.copyTo(output, bufferSize = 64 * 1024) }
                } ?: throw java.io.IOException("Dosya açılamadı")
                // null = not an image. `setOwnAvatar(null)` means "remove" and
                // would publish the removal to every contact.
                val compressed = ImagePreview.compressFile(tempFile, AVATAR_MAX_DIMENSION, AVATAR_JPEG_QUALITY)
                    ?: throw java.io.IOException("Not an image")
                withContext(Dispatchers.Main) { setOwnAvatar(compressed) }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    Toast.makeText(app, R.string.error_attachment_open_failed, Toast.LENGTH_SHORT).show()
                }
            } finally {
                tempFile.delete()
            }
        }
    }

    private fun setOwnAvatar(avatarJpeg: ByteArray?) {
        ownAvatarBytes = avatarJpeg
        AvatarUtil.renderInto(imgOwnAvatar, avatarJpeg, try {
            P2PLib.getDisplayName().ifEmpty { P2PLib.getIdentityShortCode() }
        } catch (e: Exception) { "?" })
        lifecycleScope.launch(Dispatchers.IO) {
            val result = try {
                P2PLib.setOwnProfilePicture(avatarJpeg)
            } catch (e: Exception) {
                "Error: ${e.message}"
            }
            if (result.startsWith("Error:")) {
                withContext(Dispatchers.Main) {
                    Toast.makeText(requireContext(), com.p2p.messenger.util.coreErrorText(requireContext(), result), Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    /** Spec dışı, kullanıcı isteği (Tor): Rust `torStatus()`'u yoklar ve
     *  etiketi günceller. Dönüş "ready|<host>.onion" ise host'u da gösterir. */
    private fun startTorStatusPolling() {
        torStatusHandler.removeCallbacks(torStatusRunnable)
        torStatusHandler.post(torStatusRunnable)
    }

    /** bkz. `torStatusRunnable` — yoklama yalnızca ekran öndeyken çalışır. */
    override fun onResume() {
        super.onResume()
        startTorStatusPolling()
    }

    override fun onPause() {
        super.onPause()
        torStatusHandler.removeCallbacks(torStatusRunnable)
    }

    private fun updateTorStatusLabel() {
        val label = torStatusView ?: return
        // `torStatus()` bir JNI çağrısı ve çekirdek kilidi alıyor: ana
        // thread'de yapılmaz.
        lifecycleScope.launch {
            val raw = withContext(Dispatchers.IO) {
                try {
                    P2PLib.torStatus()
                } catch (e: Exception) {
                    "failed"
                }
            }
            if (torStatusView !== label) return@launch
            val state = raw.substringBefore('|')
            label.text = when (state) {
                "bootstrapping" -> getString(R.string.tor_status_bootstrapping)
                "ready" -> {
                    val host = raw.substringAfter('|', "")
                    if (host.isNotEmpty()) getString(R.string.tor_status_ready) + "\n" + host
                    else getString(R.string.tor_status_ready)
                }
                "failed" -> getString(R.string.tor_status_failed)
                else -> getString(R.string.tor_status_disabled)
            }
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        torStatusHandler.removeCallbacks(torStatusRunnable)
        torStatusView = null
    }

    // -----------------------------------------------------------------
    // Sunucular (store-and-forward) — bkz. Rust `server_client` modülü
    // -----------------------------------------------------------------
    //
    // Rölelerden FARKLI oldukları için ayrı bir bölüm: bir röle hiçbir şey
    // SAKLAMAZ (sadece iki taraf da o anda bağlıyken canlı bir devre kurar),
    // sunucu ise alıcı çevrimdışıyken zarfı diske yazar. Kullanıcı için
    // görünen fark tam olarak budur ve tek bir "adres ekle" kutusunda
    // birleştirilirse yanlış beklenti yaratır.

    private var serversContainer: LinearLayout? = null

    /** Sunucu QR'ı taramak için — bkz. QrScanActivity.MODE_ADD_SERVER. */
    private val scanServerLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { refreshServers() }

    private fun setupServers(view: View) {
        serversContainer = view.findViewById(R.id.servers_container)

        view.findViewById<Button>(R.id.btn_add_server).setOnClickListener {
            val intent = Intent(requireContext(), QrScanActivity::class.java)
            intent.putExtra(QrScanActivity.EXTRA_MODE, QrScanActivity.MODE_ADD_SERVER)
            scanServerLauncher.launch(intent)
        }

        view.findViewById<Button>(R.id.btn_add_server_paste).setOnClickListener {
            showPasteServerCodeDialog()
        }

        refreshServers()
    }

    private fun showPasteServerCodeDialog() {
        val input = EditText(requireContext()).apply {
            hint = getString(R.string.dlg_add_server_hint)
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
            setSingleLine(false)
            maxLines = 4
        }
        AlertDialog.Builder(requireContext())
            .setTitle(R.string.dlg_add_server_title)
            .setView(input)
            .setPositiveButton(android.R.string.ok) { _, _ ->
                addServer(input.text.toString().trim())
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun addServer(code: String) {
        if (code.isEmpty()) return
        val ctx = requireContext().applicationContext
        // Writes to disk and starts a dial under the core lock.
        lifecycleScope.launch(Dispatchers.IO) {
            val result = try {
                P2PLib.addServer(code)
            } catch (e: Exception) {
                "Error: ${e.message}"
            }
            withContext(Dispatchers.Main) {
                if (result.startsWith("Error:")) {
                    Toast.makeText(ctx, com.p2p.messenger.util.coreErrorText(ctx, result), Toast.LENGTH_LONG).show()
                } else {
                    Toast.makeText(ctx, R.string.msg_server_added, Toast.LENGTH_SHORT).show()
                    if (view != null) refreshServers()
                }
            }
        }
    }

    /**
     * Sunucu satırlarını yeniden çizer.
     *
     * Satır sayısı değişken olduğu için XML'de sabit değil, programatik —
     * ama görünüm ayarlardaki diğer bölümlerle aynı (kalın 16sp başlık,
     * 12sp %70 opak açıklama, `?attr/materialButtonOutlinedStyle` butonlar,
     * `SwitchMaterial`).
     */
    private fun refreshServers() {
        if (serversContainer == null) return

        // fixpass (glm A3): `listServers()` JNI — off the main thread; rows are
        // built back on the main thread.
        lifecycleScope.launch(Dispatchers.IO) {
            val json = try {
                P2PLib.listServers()
            } catch (e: Exception) {
                "[]"
            }
            val arr = try {
                org.json.JSONArray(json)
            } catch (e: Exception) {
                org.json.JSONArray()
            }
            val rows = (0 until arr.length()).mapNotNull { arr.optJSONObject(it) }
            withContext(Dispatchers.Main) {
                val fresh = serversContainer ?: return@withContext
                // Cleared here, not before the read: two refreshes in flight
                // (screen opened + scan result) both appended their rows.
                fresh.removeAllViews()
                for (obj in rows) fresh.addView(buildServerRow(obj))
            }
        }
    }

    private fun buildServerRow(obj: org.json.JSONObject): View {
        val serverId = obj.optString("server_id")
        val ctx = requireContext()
        val density = resources.displayMetrics.density
        fun dp(v: Int) = (v * density).toInt()

        val row = LinearLayout(ctx).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(12), dp(12), dp(12), dp(12))
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = dp(8) }
            setBackgroundColor(
                MaterialColors.getColor(this, com.google.android.material.R.attr.colorSurfaceContainerHigh)
            )
        }

        val name = obj.optString("name").ifEmpty { obj.optString("address") }
        row.addView(TextView(ctx).apply {
            text = name
            textSize = 14f
            setTypeface(typeface, android.graphics.Typeface.BOLD)
        })

        // Durum: bağlı+kayıtlı / bağlanıyor / kayıtlı değil. Kayıt, operatörün
        // yayımladığı katılım koduyla yapılır ve başarısız olursa sebebi
        // burada görünür (`last_error`).
        val connected = obj.optBoolean("connected")
        val enrolled = obj.optBoolean("enrolled")
        val lastError = obj.optString("last_error").takeIf { it.isNotEmpty() && it != "null" }
        val stateText = when {
            lastError != null -> lastError
            connected && enrolled -> getString(R.string.state_server_connected)
            connected -> getString(R.string.state_server_not_enrolled)
            else -> getString(R.string.state_server_connecting)
        }
        row.addView(TextView(ctx).apply {
            text = stateText
            textSize = 12f
            alpha = 0.7f
        })

        row.addView(SwitchMaterial(ctx).apply {
            text = getString(R.string.lbl_server_route)
            isChecked = obj.optBoolean("route_messages")
            setOnCheckedChangeListener { button, checked ->
                applyServerToggle(button, checked) { P2PLib.setServerRouting(serverId, checked) }
            }
        })

        row.addView(SwitchMaterial(ctx).apply {
            text = getString(R.string.lbl_server_history)
            isChecked = obj.optBoolean("store_history")
            setOnCheckedChangeListener { button, checked ->
                applyServerToggle(button, checked) {
                    // Kök arşiv anahtarı (ARK) SADECE burada üretilir —
                    // bkz. ArchiveKeyManager: açılışta kendiliğinden
                    // üretilseydi, kardeşinden anahtar almadan önce açılan
                    // bir cihaz kendi rastgele anahtarını kullanır ve
                    // yüklediği arşiv diğer cihazlarda okunamaz olurdu.
                    if (checked && !revertingServerToggle && !ArchiveKeyManager.ensureCreated(ctx.applicationContext)) {
                        "Error: archive key unavailable"
                    } else {
                        P2PLib.setServerHistory(serverId, checked)
                    }
                }
            }
        })

        row.addView(TextView(ctx).apply {
            text = getString(R.string.lbl_server_history_warn)
            textSize = 12f
            alpha = 0.7f
        })

        // Sıfırdan kurulan bir cihaz için: yukarı kaydırma akışı sohbetin
        // zaten görünür olmasını varsayıyor, ama burada hiç mesaj yok ve
        // kaydırılacak bir şey de yok.
        row.addView(Button(ctx, null, com.google.android.material.R.attr.materialButtonOutlinedStyle).apply {
            text = getString(R.string.action_restore_history)
            setOnClickListener {
                lifecycleScope.launch(Dispatchers.IO) {
                    val result = try {
                        P2PLib.restoreServerHistory()
                    } catch (e: Exception) {
                        "Error: ${e.message}"
                    }
                    withContext(Dispatchers.Main) {
                        val msg = if (result.startsWith("Error:")) com.p2p.messenger.util.coreErrorText(ctx, result)
                        else ctx.getString(R.string.msg_restore_started)
                        Toast.makeText(ctx, msg, Toast.LENGTH_LONG).show()
                    }
                }
            }
        })

        row.addView(Button(ctx, null, com.google.android.material.R.attr.materialButtonOutlinedStyle).apply {
            text = getString(R.string.action_remove_server)
            setTextColor(MaterialColors.getColor(this, com.google.android.material.R.attr.colorError))
            setOnClickListener {
                // fixpass (glm A3): `removeServer` JNI — off the main thread.
                lifecycleScope.launch(Dispatchers.IO) {
                    try {
                        P2PLib.removeServer(serverId)
                    } catch (e: Exception) {
                        // yok sayılır — liste zaten yenilenecek
                    }
                    withContext(Dispatchers.Main) {
                        Toast.makeText(ctx, R.string.msg_server_removed, Toast.LENGTH_SHORT).show()
                        refreshServers()
                    }
                }
            }
        })

        return row
    }

}
