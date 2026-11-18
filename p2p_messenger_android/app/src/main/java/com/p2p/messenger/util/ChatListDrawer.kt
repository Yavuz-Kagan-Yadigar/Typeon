package com.p2p.messenger.util

import androidx.activity.OnBackPressedCallback
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.GravityCompat
import androidx.drawerlayout.widget.DrawerLayout
import com.p2p.messenger.ChatsFragment
import com.p2p.messenger.R

/**
 * The chat list drawer that slides in from the left, in ChatActivity and GroupChatActivity (see `DrawerLayout` and `chatListDrawerContainer` in
 * activity_chat.xml). One shared setup function serves both screens. The drawer itself, the `ChatsFragment` inside it, and the back button behaviour
 * must be identical on both screens.
 */
object ChatListDrawer {

    /**
     * Called from `onCreate`, AFTER `setContentView`. It tells the `ChatsFragment` inside the drawer (created automatically by the `android:name` on the
     * `FragmentContainerView` in activity_chat.xml) that tapping a chat must close THIS activity. Otherwise every chat opened from the drawer would create a
     * new Activity stacked on top, and the back button would unwind an endless stack.
     *
     * Back button: while the drawer is open, it only closes the drawer (it does NOT leave the chat). That is the standard `DrawerLayout` behaviour. It stops
     * the surprise of "I opened the drawer by mistake, pressed back, and left the whole chat".
     */
    fun setup(activity: AppCompatActivity, onBack: () -> Boolean = { false }): DrawerLayout? {
        val drawer = activity.findViewById<DrawerLayout>(R.id.chatDrawerLayout) ?: return null
        val fragment = activity.supportFragmentManager
            .findFragmentById(R.id.chatListDrawerContainer) as? ChatsFragment
        fragment?.onChatOpenedFromDrawer = { activity.finish() }
        fragment?.inClosedDrawer = { !drawer.isDrawerOpen(GravityCompat.START) }
        drawer.addDrawerListener(object : DrawerLayout.SimpleDrawerListener() {
            // From the first drag, so the list is fresh while it slides in.
            override fun onDrawerStateChanged(newState: Int) { if (newState != DrawerLayout.STATE_IDLE) fragment?.onDrawerOpened() }
            override fun onDrawerOpened(drawerView: android.view.View) { fragment?.onDrawerOpened() }
        })

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
}
