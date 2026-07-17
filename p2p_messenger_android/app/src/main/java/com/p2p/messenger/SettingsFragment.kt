package com.p2p.messenger

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import com.google.android.material.switchmaterial.SwitchMaterial
import com.p2p.messenger.service.P2PService
import com.p2p.messenger.util.ThemePrefs

class SettingsFragment : Fragment() {
    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View? {
        val view = inflater.inflate(R.layout.fragment_settings, container, false)

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
}
