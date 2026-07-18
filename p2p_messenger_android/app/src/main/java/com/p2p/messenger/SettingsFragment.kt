package com.p2p.messenger

import android.net.Uri
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.ImageView
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import com.google.android.material.switchmaterial.SwitchMaterial
import com.p2p.messenger.service.P2PService
import com.p2p.messenger.util.AvatarUtil
import com.p2p.messenger.util.ImagePreview
import com.p2p.messenger.util.ThemePrefs
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.util.UUID

class SettingsFragment : Fragment() {

    companion object {
        /** bkz. ChatActivity PREVIEW_MAX_DIMENSION notu — kullanıcı
         *  tarafından istenen profil fotoğrafı standardı: 720p/%85 JPEG
         *  (sohbet eki önizlemelerinden — 480p — daha büyük, çünkü profil
         *  fotoğrafı tam ekran/daha büyük gösterilebilir). */
        private const val AVATAR_MAX_DIMENSION = 720
        private const val AVATAR_JPEG_QUALITY = 85
    }

    private lateinit var imgOwnAvatar: ImageView

    /** Spec dışı, kullanıcı isteği (Tor): durum etiketi + periyodik yoklama. */
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

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View? {
        val view = inflater.inflate(R.layout.fragment_settings, container, false)

        imgOwnAvatar = view.findViewById(R.id.img_own_avatar)
        refreshOwnAvatar()
        view.findViewById<Button>(R.id.btn_change_picture).setOnClickListener {
            pickAvatarLauncher.launch(arrayOf("image/*"))
        }
        view.findViewById<Button>(R.id.btn_remove_picture).setOnClickListener {
            setOwnAvatar(null)
        }

        val identityCodeValue = view.findViewById<android.widget.TextView>(R.id.identity_code_value)
        identityCodeValue.text = try {
            P2PLib.getIdentityCode()
        } catch (e: Exception) {
            ""
        }

        val nodeModeSwitch = view.findViewById<SwitchMaterial>(R.id.node_mode_switch)
        nodeModeSwitch.isChecked = P2PService.isNodeModeEnabled(requireContext())
        nodeModeSwitch.setOnCheckedChangeListener { _, isChecked ->
            P2PService.setNodeModeEnabled(requireContext(), isChecked)
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
        }
        startTorStatusPolling()

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
                Toast.makeText(requireContext(), result, Toast.LENGTH_SHORT).show()
            } else {
                relayAddressInput.text.clear()
                Toast.makeText(requireContext(), R.string.msg_relay_address_added, Toast.LENGTH_SHORT).show()
            }
        }

        // OLED siyah: ThemeOverlay Activity oluşturulmadan önce (bkz.
        // P2PApplication.onActivityPreCreated) uygulandığından, tercih
        // değiştiğinde geçerli olması için Activity'nin yeniden
        // oluşturulması (recreate) gerekiyor.
        val oledBlackSwitch = view.findViewById<SwitchMaterial>(R.id.oled_black_switch)
        oledBlackSwitch.isChecked = ThemePrefs.isOledBlackEnabled(requireContext())
        oledBlackSwitch.setOnCheckedChangeListener { _, isChecked ->
            ThemePrefs.setOledBlackEnabled(requireContext(), isChecked)
            requireActivity().recreate()
        }

        // Anahtarların donanım güvenlik modülünde (StrongBox/TEE) tutulup
        // tutulmadığını göster — kullanıcıya somut bir güvenlik göstergesi.
        val securityStatus = view.findViewById<android.widget.TextView>(R.id.key_security_status)
        securityStatus.text = if (com.p2p.messenger.util.KeystoreCrypto.isHardwareBacked()) {
            getString(R.string.lbl_keys_hardware_backed)
        } else {
            getString(R.string.lbl_keys_software_backed)
        }

        return view
    }

    private fun refreshOwnAvatar() {
        val bytes = try {
            P2PLib.getOwnProfilePicture().takeIf { it.isNotEmpty() }
        } catch (e: Exception) {
            null
        }
        val name = try {
            P2PLib.getIdentityShortCode()
        } catch (e: Exception) {
            "?"
        }
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
        lifecycleScope.launch(Dispatchers.IO) {
            val tempFile = File(File(requireContext().cacheDir, "avatar").apply { mkdirs() }, UUID.randomUUID().toString())
            try {
                requireContext().contentResolver.openInputStream(uri)?.use { input ->
                    tempFile.outputStream().use { output -> input.copyTo(output, bufferSize = 64 * 1024) }
                } ?: throw java.io.IOException("Dosya açılamadı")
                val compressed = ImagePreview.compressFile(tempFile, AVATAR_MAX_DIMENSION, AVATAR_JPEG_QUALITY)
                withContext(Dispatchers.Main) { setOwnAvatar(compressed) }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    Toast.makeText(requireContext(), R.string.error_attachment_open_failed, Toast.LENGTH_SHORT).show()
                }
            } finally {
                tempFile.delete()
            }
        }
    }

    private fun setOwnAvatar(avatarJpeg: ByteArray?) {
        AvatarUtil.renderInto(imgOwnAvatar, avatarJpeg, try { P2PLib.getIdentityShortCode() } catch (e: Exception) { "?" })
        lifecycleScope.launch(Dispatchers.IO) {
            val result = try {
                P2PLib.setOwnProfilePicture(avatarJpeg)
            } catch (e: Exception) {
                "Error: ${e.message}"
            }
            if (result.startsWith("Error:")) {
                withContext(Dispatchers.Main) {
                    Toast.makeText(requireContext(), result, Toast.LENGTH_SHORT).show()
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

    private fun updateTorStatusLabel() {
        val label = torStatusView ?: return
        val raw = try {
            P2PLib.torStatus()
        } catch (e: Exception) {
            "failed"
        }
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

    override fun onDestroyView() {
        super.onDestroyView()
        torStatusHandler.removeCallbacks(torStatusRunnable)
        torStatusView = null
    }
}
