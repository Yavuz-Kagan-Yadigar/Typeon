package com.p2p.messenger.ui

import android.app.Dialog
import android.content.Context
import android.graphics.BitmapFactory
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.TextView
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.p2p.messenger.R
import com.p2p.messenger.util.AvatarUtil
import com.p2p.messenger.util.ImagePreview

/**
 * Adapter for the chat and contact list. It uses `ListAdapter` with `DiffUtil`, so that when the list changes (a new contact, a changed
 * last message, and so on) only the changed rows are updated, with animation. `notifyDataSetChanged()` would redraw everything. On
 * long contact lists that makes a visible difference in speed and smoothness.
 */
class ChatAdapter(
    private val onItemClick: (ChatMessage) -> Unit
) : ListAdapter<ChatAdapter.ChatMessage, ChatAdapter.ChatViewHolder>(DIFF_CALLBACK) {

    data class ChatMessage(
        val contactId: String,
        val displayName: String,
        val lastMessage: String,
        val timestamp: Long,
        /** True if this conversation has activity since it was last opened
         *  (see ReadStatePrefs) — drives the row's accent-tinted background. */
        val hasUnread: Boolean = false,
        /** See PinnedChatsPrefs — pinned rows always sort above unpinned
         *  ones (ChatsFragment.refreshList) and get a 📌 prefix on the name. */
        val isPinned: Boolean = false,
        /** The real `contact_id` from Rust. The `contactId` field historically carries the DEVICE fingerprint (see the ChatsFragment note).
         *  It is needed only for the clear-history and delete-contact calls of the long-press menu. Empty on group rows. */
        val realContactId: String = "",
        /** Profile photo of this contact or group (720p, 85% JPEG), or `null`. The initial badge is shown when it is `null`. */
        val avatarJpeg: ByteArray? = null,
        /** The Groups tab was removed, and groups were merged into this list. When `true`, `contactId` is really a `group_id`, and a tap
         *  must open `GroupChatActivity`. */
        val isGroup: Boolean = false,
        /** `true` when this person was added through a group (vouched for by the founder), not by an in-person QR. A warning mark is shown on
         *  the row (see Rust `Contact.added_via_group`). */
        val addedViaGroup: Boolean = false,
        /** On `isGroup` rows: whether WE are the founder of this group. The "Delete group for everyone" option is shown only to the founder. */
        val isGroupFounder: Boolean = false,
        /** Blocking targets the PERSON (identity), not a device. So the long-press menu needs the `identity_id`. `contactId` historically
         *  carries the device fingerprint, which does not do the job. Empty on group rows. */
        val identityId: String = ""
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is ChatMessage) return false
            return contactId == other.contactId && displayName == other.displayName &&
                lastMessage == other.lastMessage && timestamp == other.timestamp &&
                hasUnread == other.hasUnread &&
                isPinned == other.isPinned &&
                realContactId == other.realContactId && identityId == other.identityId &&
                isGroup == other.isGroup &&
                // `DiffUtil.ItemCallback.areContentsTheSame` uses this `equals`, so every field that `bind` shows must be compared here.
                // Otherwise a row whose only change is `addedViaGroup` (the "unverified" mark) is not rebound.
                addedViaGroup == other.addedViaGroup && isGroupFounder == other.isGroupFounder &&
                (avatarJpeg?.contentEquals(other.avatarJpeg) ?: (other.avatarJpeg == null))
        }

        override fun hashCode(): Int {
            var result = contactId.hashCode()
            result = 31 * result + displayName.hashCode()
            result = 31 * result + lastMessage.hashCode()
            result = 31 * result + timestamp.hashCode()
            result = 31 * result + hasUnread.hashCode()
            result = 31 * result + isPinned.hashCode()
            result = 31 * result + realContactId.hashCode()
            result = 31 * result + isGroup.hashCode()
            result = 31 * result + addedViaGroup.hashCode()
            result = 31 * result + isGroupFounder.hashCode()
            result = 31 * result + (avatarJpeg?.contentHashCode() ?: 0)
            return result
        }
    }

    companion object {
        private val DIFF_CALLBACK = object : DiffUtil.ItemCallback<ChatMessage>() {
            override fun areItemsTheSame(old: ChatMessage, new: ChatMessage) =
                old.contactId == new.contactId

            override fun areContentsTheSame(old: ChatMessage, new: ChatMessage) =
                old == new
        }
    }

    /** Called on long press of a contact row. The clear-history and delete-contact menu is shown by ChatsFragment and ContactsFragment. */
    var onContactLongClick: ((ChatMessage) -> Unit)? = null

    inner class ChatViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        private val txtName: TextView = itemView.findViewById(R.id.txtContactName)
        private val txtLastMessage: TextView = itemView.findViewById(R.id.txtLastMessage)
        private val txtTimestamp: TextView = itemView.findViewById(R.id.txtTimestamp)
        private val imgAvatar: ImageView = itemView.findViewById(R.id.imgAvatar)

        /** only the relative time label (no avatar decode, no rebind). */
        fun bindTime(message: ChatMessage) {
            txtTimestamp.text = if (message.timestamp > 0) formatTimestamp(message.timestamp) else ""
        }

        fun bind(message: ChatMessage) {
            // Contacts added through a group (vouched for by the founder) were not verified in person with QR. A visible warning mark on the name.
            val pinPrefix = if (message.isPinned) "📌 " else ""
            val warnPrefix = if (message.addedViaGroup) "⚠ " else ""
            txtName.text = "$pinPrefix$warnPrefix${message.displayName}"
            txtLastMessage.text = message.lastMessage
            txtTimestamp.text = if (message.timestamp > 0) formatTimestamp(message.timestamp) else ""
            AvatarUtil.renderInto(imgAvatar, message.avatarJpeg, message.displayName)

            // Avatar tap shows the photo full screen; with no photo (letter
            // badge) it still opens the chat. Long-press stays on the row.
            imgAvatar.setOnClickListener {
                val bytes = message.avatarJpeg
                if (bytes == null || bytes.isEmpty()) onItemClick(message)
                else showAvatarFullscreen(itemView.context, bytes)
            }
            imgAvatar.setOnLongClickListener { itemView.performLongClick() }

            // Unread rows get a 20%-alpha accent color overlay on top of the
            // normal background; cleared once ReadStatePrefs marks it read.
            itemView.setBackgroundColor(
                if (message.hasUnread) {
                    val accent = com.google.android.material.color.MaterialColors.getColor(
                        itemView, com.google.android.material.R.attr.colorPrimary
                    )
                    androidx.core.graphics.ColorUtils.setAlphaComponent(accent, (255 * 0.20f).toInt())
                } else {
                    android.graphics.Color.TRANSPARENT
                }
            )

            itemView.setOnClickListener {
                onItemClick(message)
            }
            itemView.setOnLongClickListener {
                // Group rows have no realContactId, so the long-press menu is also allowed for isGroup rows (delete group for the founder).
                if (message.isGroup || message.realContactId.isNotEmpty()) {
                    onContactLongClick?.invoke(message)
                    true
                } else {
                    false
                }
            }
        }

        private fun formatTimestamp(timestamp: Long): String {
            val now = System.currentTimeMillis()
            val diff = now - timestamp
            val context = itemView.context
            return when {
                diff < 60000 -> context.getString(R.string.lbl_time_just_now)
                diff < 3600000 -> context.getString(R.string.lbl_time_minutes_ago, diff / 60000)
                diff < 86400000 -> context.getString(R.string.lbl_time_hours_ago, diff / 3600000)
                else -> context.getString(R.string.lbl_time_days_ago, diff / 86400000)
            }
        }
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ChatViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_chat, parent, false)
        return ChatViewHolder(view)
    }

    override fun onBindViewHolder(holder: ChatViewHolder, position: Int) {
        holder.bind(getItem(position))
    }

    override fun onBindViewHolder(holder: ChatViewHolder, position: Int, payloads: MutableList<Any>) {
        if (payloads.contains(TIME_PAYLOAD)) holder.bindTime(getItem(position)) else super.onBindViewHolder(holder, position, payloads)
    }

    private val TIME_PAYLOAD = Any()
    private var labelsMinute = 0L

    /** Updates the time labels ("just now", "5 min ago") at most once a minute. Called on every list refresh. */
    fun refreshTimeLabels() {
        val minute = System.currentTimeMillis() / 60_000
        if (minute == labelsMinute) return
        labelsMinute = minute
        notifyItemRangeChanged(0, itemCount, TIME_PAYLOAD)
    }
}

/** Full-screen raw avatar JPEG in a plain Dialog — no temp file on disk
 *  (unlike AvatarUtil.openFullscreen, which needs a URI for MediaViewer). */
private fun showAvatarFullscreen(context: Context, bytes: ByteArray) {
    val bitmap = ImagePreview.decodeBytes(bytes, 2048) ?: return
    val dialog = Dialog(context, android.R.style.Theme_Black_NoTitleBar_Fullscreen)
    val image = ImageView(context).apply {
        setImageBitmap(bitmap)
        scaleType = ImageView.ScaleType.FIT_CENTER
        setOnClickListener { dialog.dismiss() }
    }
    dialog.setContentView(image, ViewGroup.LayoutParams(
        ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT
    ))
    // Bound to the screen: a recreate must not leak the window.
    (context as? androidx.lifecycle.LifecycleOwner)?.lifecycle?.addObserver(object : androidx.lifecycle.DefaultLifecycleObserver {
        override fun onDestroy(owner: androidx.lifecycle.LifecycleOwner) { dialog.dismiss() }
    })
    dialog.show()
}
