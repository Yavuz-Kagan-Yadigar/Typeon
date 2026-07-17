package com.p2p.messenger

import android.app.AlertDialog
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.Toast
import androidx.fragment.app.Fragment
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.p2p.messenger.ui.GroupAdapter
import com.p2p.messenger.ui.GroupChatActivity
import org.json.JSONArray

/**
 * Spec 5 (Grup mesajlaşma) — grup listesi + oluşturma/üye ekleme GUI'si.
 * Tıklama gerçek grup sohbetini (GroupChatActivity) açar; uzun basma üye
 * listesi/ekleme dialogunu gösterir.
 */
class GroupsFragment : Fragment() {

    private lateinit var adapter: GroupAdapter
    private lateinit var recycler: RecyclerView
    private lateinit var noGroupsText: View

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View? {
        val view = inflater.inflate(R.layout.fragment_groups, container, false)

        noGroupsText = view.findViewById(R.id.txtNoGroups)
        recycler = view.findViewById(R.id.recyclerGroups)
        recycler.layoutManager = LinearLayoutManager(requireContext())
        adapter = GroupAdapter(
            onGroupClick = { group -> openGroupChat(group) },
            onGroupLongClick = { group -> showGroupDetailDialog(group) }
        )
        recycler.adapter = adapter

        view.findViewById<Button>(R.id.btn_create_group).setOnClickListener {
            showCreateGroupDialog()
        }

        refreshGroups()
        return view
    }

    override fun onResume() {
        super.onResume()
        refreshGroups()
    }

    private fun refreshGroups() {
        val json = try {
            P2PLib.listGroups()
        } catch (e: Exception) {
            "[]"
        }
        val array = try {
            JSONArray(json)
        } catch (e: Exception) {
            JSONArray()
        }
        val rows = (0 until array.length()).map { i ->
            val obj = array.getJSONObject(i)
            val members = obj.optJSONArray("member_identity_ids")
            val memberIds = (0 until (members?.length() ?: 0)).map { members!!.getString(it) }
            GroupAdapter.GroupRow(
                groupId = obj.optString("group_id"),
                name = obj.optString("name"),
                founderIdentityId = obj.optString("founder_identity_id"),
                isFounder = obj.optBoolean("is_founder"),
                memberIdentityIds = memberIds
            )
        }
        noGroupsText.visibility = if (rows.isEmpty()) View.VISIBLE else View.GONE
        recycler.visibility = if (rows.isEmpty()) View.GONE else View.VISIBLE
        adapter.submitList(rows)
    }

    private fun showCreateGroupDialog() {
        val input = EditText(requireContext())
        input.hint = getString(R.string.lbl_new_group_name_hint)
        AlertDialog.Builder(requireContext())
            .setTitle(R.string.action_create_group)
            .setView(input)
            .setPositiveButton(R.string.action_create_group) { _, _ ->
                val name = input.text.toString().trim()
                if (name.isBlank()) return@setPositiveButton
                val groupId = P2PLib.createGroup(name)
                if (groupId.startsWith("Error:")) {
                    Toast.makeText(requireContext(), groupId, Toast.LENGTH_LONG).show()
                } else {
                    refreshGroups()
                    showAddMembersDialog(groupId)
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    /** Kişi listesinden çoklu seçimle grup üyesi ekler (bkz. spec 5.4 —
     *  kurucu davet üretir, her davet edilen mevcut/kurulmakta olan 1:1
     *  bağlantı üzerinden GroupUpdate alır). */
    private fun showAddMembersDialog(groupId: String) {
        val contactsJson = try {
            P2PLib.listContacts()
        } catch (e: Exception) {
            "[]"
        }
        val array = try {
            JSONArray(contactsJson)
        } catch (e: Exception) {
            JSONArray()
        }
        if (array.length() == 0) {
            Toast.makeText(requireContext(), R.string.msg_no_contacts_to_add, Toast.LENGTH_LONG).show()
            return
        }
        val names = (0 until array.length()).map { array.getJSONObject(it).optString("display_name", "Bilinmeyen") }.toTypedArray()
        val identityIds = (0 until array.length()).map { array.getJSONObject(it).optString("identity_id") }
        val checked = BooleanArray(names.size)

        AlertDialog.Builder(requireContext())
            .setTitle(R.string.lbl_add_member_to_group)
            .setMultiChoiceItems(names, checked) { _, which, isChecked -> checked[which] = isChecked }
            .setPositiveButton(R.string.lbl_add_member_to_group) { _, _ ->
                for (i in identityIds.indices) {
                    if (checked[i]) {
                        val ok = P2PLib.inviteToGroup(groupId, identityIds[i])
                        if (!ok) {
                            Toast.makeText(requireContext(), "${names[i]}: ${getString(R.string.error_network)}", Toast.LENGTH_SHORT).show()
                        }
                    }
                }
                refreshGroups()
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun openGroupChat(group: GroupAdapter.GroupRow) {
        val intent = android.content.Intent(requireContext(), GroupChatActivity::class.java)
        intent.putExtra(GroupChatActivity.EXTRA_GROUP_ID, group.groupId)
        intent.putExtra(GroupChatActivity.EXTRA_GROUP_NAME, group.name)
        startActivity(intent)
    }

    private fun showGroupDetailDialog(group: GroupAdapter.GroupRow) {
        val message = buildString {
            append(resources.getQuantityString(R.plurals.lbl_member_count, group.memberIdentityIds.size, group.memberIdentityIds.size))
            append("\n\n")
            append(group.memberIdentityIds.joinToString("\n") { it.take(16) + "..." })
        }

        val builder = AlertDialog.Builder(requireContext())
            .setTitle(group.name)
            .setMessage(message)
            .setNegativeButton(android.R.string.ok, null)
        if (group.isFounder) {
            builder.setPositiveButton(R.string.lbl_add_member_to_group) { _, _ -> showAddMembersDialog(group.groupId) }
        }
        builder.show()
    }
}
