package com.p2p.messenger.util

import androidx.activity.OnBackPressedCallback
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.GravityCompat
import androidx.drawerlayout.widget.DrawerLayout
import com.p2p.messenger.ChatsFragment
import com.p2p.messenger.R

/**
 * Spec dışı, kullanıcı isteği: "soldan bir drag barla sürüklenebilir açılıp
 * kapanan chat list" — ChatActivity/GroupChatActivity'nin soldan açılan
 * sohbet listesi çekmecesi (bkz. activity_chat.xml `DrawerLayout` +
 * `chatListDrawerContainer`). İkisi arasında paylaşılan tek bir kurulum
 * fonksiyonu — çekmecenin kendisi, içindeki `ChatsFragment` örneği ve geri
 * tuşu davranışı HER İKİ ekranda da birebir aynı olmalı.
 */
object ChatListDrawer {

    /**
     * `onCreate`'ten, `setContentView`'den SONRA çağrılır. Çekmece içindeki
     * `ChatsFragment`'e (bkz. `activity_chat.xml` `android:name` ile
     * kendiliğinden oluşturulan `FragmentContainerView`) bir sohbete
     * dokunulduğunda BU activity'yi kapatmasını söyler — aksi halde
     * çekmeceden açılan her sohbet, üstüne yığılan yeni bir Activity
     * yaratır ve geri tuşu sonsuz bir yığını geriye sarardı.
     *
     * Geri tuşu: çekmece açıkken SADECE onu kapatır (sohbetten ÇIKMAZ) —
     * standart `DrawerLayout` davranışı, kullanıcının "yanlışlıkla çekmeceyi
     * açtım, geri tuşuna bastım, tüm sohbetten çıktım" şaşkınlığını önler.
     */
    fun setup(activity: AppCompatActivity, onBack: () -> Boolean = { false }): DrawerLayout? {
        val drawer = activity.findViewById<DrawerLayout>(R.id.chatDrawerLayout) ?: return null
        val fragment = activity.supportFragmentManager
            .findFragmentById(R.id.chatListDrawerContainer) as? ChatsFragment
        fragment?.onChatOpenedFromDrawer = { activity.finish() }

        activity.onBackPressedDispatcher.addCallback(activity, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                if (drawer.isDrawerOpen(GravityCompat.START)) {
                    drawer.closeDrawer(GravityCompat.START)
                } else if (onBack()) {
                    // The screen used Back itself (closed its search bar).
                } else {
                    activity.finish()
                }
            }
        })
        return drawer
    }

    /** bkz. `menu_chat_search.xml` `action_open_chat_list` — araç çubuğu
     *  simgesiyle açma (kenardan kaydırma jestine ek, keşfedilebilirlik
     *  için). */
    fun open(activity: AppCompatActivity) {
        activity.findViewById<DrawerLayout>(R.id.chatDrawerLayout)?.openDrawer(GravityCompat.START)
    }
}
