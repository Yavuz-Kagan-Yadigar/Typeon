package com.p2p.messenger.ui

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.p2p.messenger.R

/** Groups tab GUI'sindeki grup listesi — bkz. GroupsFragment. Tıklama grup
 *  sohbetini (GroupChatActivity) açar, uzun basma üye listesi/ekleme
 *  dialogunu gösterir. */
class GroupAdapter(
    private val onGroupClick: (GroupRow) -> Unit,
    private val onGroupLongClick: (GroupRow) -> Unit
) : RecyclerView.Adapter<GroupAdapter.GroupViewHolder>() {

    data class GroupRow(
        val groupId: String,
        val name: String,
        val founderIdentityId: String,
        val isFounder: Boolean,
        val memberIdentityIds: List<String>
    )

    private val items = mutableListOf<GroupRow>()

    fun submitList(newItems: List<GroupRow>) {
        items.clear()
        items.addAll(newItems)
        notifyDataSetChanged()
    }

    class GroupViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        val name: TextView = itemView.findViewById(R.id.txtGroupName)
        val memberCount: TextView = itemView.findViewById(R.id.txtGroupMemberCount)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): GroupViewHolder {
        val view = LayoutInflater.from(parent.context).inflate(R.layout.item_group, parent, false)
        return GroupViewHolder(view)
    }

    override fun onBindViewHolder(holder: GroupViewHolder, position: Int) {
        val item = items[position]
        holder.name.text = item.name
        holder.memberCount.text = holder.itemView.context.resources.getQuantityString(
            R.plurals.lbl_member_count, item.memberIdentityIds.size, item.memberIdentityIds.size
        )
        holder.itemView.setOnClickListener { onGroupClick(item) }
        holder.itemView.setOnLongClickListener { onGroupLongClick(item); true }
    }

    override fun getItemCount(): Int = items.size
}
