package com.p2p.messenger

import android.app.AlertDialog
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.widget.SearchView
import androidx.fragment.app.Fragment
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.floatingactionbutton.FloatingActionButton
import com.p2p.messenger.ui.ChatActivity
import com.p2p.messenger.ui.ChatAdapter
import com.p2p.messenger.ui.GroupChatActivity
import com.p2p.messenger.util.PinnedChatsPrefs
import com.p2p.messenger.util.ReadStatePrefs
import com.p2p.messenger.util.hexToBytes
import org.json.JSONArray
import org.json.JSONObject

/**
 * Spec 3 minimum kapsamı: bilinen kişilerin + grupların TEK bir listesi,
 * tıklanınca ilgili sohbet ekranını açar. `ListAdapter`/`DiffUtil` tabanlı
 * gerçek bir adapter kullanır (bkz. ChatAdapter) ve periyodik olarak
 * yenilenir. En güncel mesaj/ek atılan sohbet en üstte olacak şekilde
 * sıralanır (bkz. `refreshList` — hem kişiler hem gruplar, tek bir zaman
 * çizelgesinde). Node modu kapalıyken kişiler için "son mesaj" alanı boş
 * kalır (mesaj geçmişi o durumda hiç saklanmıyor) — gruplar için de aynı
 * kısıt geçerli (bkz. `archive_group_message`).
 *
 * Spec dışı: önceden ayrı bir "Gruplar" sekmesi vardı — kullanıcı isteği
 * üzerine kaldırıldı, grup listesi/oluşturma buraya taşındı (bkz.
 * `btnCreateGroup`, eski GroupsFragment'in mantığı).
 */
class ChatsFragment : Fragment() {

    companion object {
        /** Olay geldiğinde listenin yenilenmesi için beklenen süre: bir
         *  olay patlaması TEK yenileme olsun (her olayda yenilemek, eskiden
         *  5 saniyelik turdan çok daha pahalı olurdu). */
        private const val EVENT_REFRESH_DEBOUNCE_MS = 1000L
    }

    /**
     * Spec dışı, kullanıcı isteği ("soldan bir drag barla sürüklenebilir
     * açılıp kapanan chat list"): bu fragment artık İKİ yerde barınabiliyor
     * — MainActivity'nin sekmesi (normal, TAM EKRAN kullanım — bu geri
     * çağrı `null` kalır) VE ChatActivity/GroupChatActivity'nin soldan
     * açılan çekmecesi (bkz. activity_chat.xml DrawerLayout). Çekmece
     * içindeyken bir sohbete dokunmak YENİ bir ChatActivity/
     * GroupChatActivity BAŞLATIR (bkz. aşağıdaki `openGroupChat`/DM kolu) —
     * ama o zaten AÇIK olan sohbet ekranının ÜSTÜNE yığılmaması için host
     * (bkz. ChatActivity.setupChatListDrawer) bunu `{ finish() }`'e
     * ayarlar. MainActivity'nin kendi sekmesinde bu callback set
     * EDİLMEDİĞİNDEN (varsayılan `null`) davranış orada DEĞİŞMEZ.
     */
    var onChatOpenedFromDrawer: (() -> Unit)? = null

    private lateinit var adapter: ChatAdapter
    private lateinit var noContactsText: View
    /** bkz. `applyFilter` — en son çekilen TAM liste (kişi+grup); arama
     *  sorgusu buradan filtrelenir, listenin yenilenmesi arama sorgusunu
     *  SIFIRLAMAZ. */
    private var allChatItems: List<ChatAdapter.ChatMessage> = emptyList()
    private var searchQuery: String = ""

    /** Çekirdek bir hatayı "Error: ..." metniyle döner; kullanıcıya
     *  gösterilen metin kaynaktan gelir (sabit İngilizce değil). */
    private fun errorText(result: String): String =
        com.p2p.messenger.util.coreErrorText(requireContext(), result)
    private val refreshHandler = Handler(Looper.getMainLooper())
    /**
     * 5 saniyede bir TAM liste yeniden kurma YOK: her turda (ve her açık
     * sohbetin çekmecesinde) tüm kişi/grup listesi, son mesaj önizlemeleri
     * ve ekler yeniden okunuyordu — çekirdek kilidinde O(sohbet × ek) işi,
     * her 5 saniyede bir (bkz. `refreshList` notu).
     *
     * Liste artık OLAYLA tazelenir: ekrana dönüşte ve servisten bir olay
     * geldiğinde (mesaj, okundu, eşleşme, grup güncellemesi...).
     */
    /** A refresh is queued (`Handler.hasCallbacks` is API 29, minSdk 26). */
    @Volatile private var eventRefreshQueued = false
    private val eventRefreshRunnable = Runnable { eventRefreshQueued = false; refreshList() }
    private val eventListener: (String) -> Unit = { _ ->
        // Olaylar tek tek gelir (bir patlamada 50 mesaj = 50 yeniden kurma
        // olurdu): bekleyen bir yenileme varsa yenisini EKLEME.
        if (!eventRefreshQueued) {
            eventRefreshQueued = true
            refreshHandler.postDelayed(eventRefreshRunnable, EVENT_REFRESH_DEBOUNCE_MS)
        }
    }
    /** Spinner while the service leaves power save and re-verifies its links
     *  ("syncing" in `ownConnectionStatus`); refreshes the list when done.
     *  Polls off the main thread (the JNI call takes the core lock) and stops
     *  by itself once the core says it is in sync. */
    private val syncRunnable = object : Runnable {
        override fun run() {
            runOnWorker {
                val syncing = try {
                    org.json.JSONObject(P2PLib.ownConnectionStatus()).optBoolean("syncing", false)
                } catch (e: Exception) { false }
                refreshHandler.post {
                    val spinner = view?.findViewById<View>(R.id.progressSync) ?: return@post
                    if (!syncing && spinner.visibility == View.VISIBLE) refreshList()
                    spinner.visibility = if (syncing) View.VISIBLE else View.GONE
                    if (syncing && isResumed) refreshHandler.postDelayed(this, 400)
                }
            }
        }
    }

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View? {
        val view = inflater.inflate(R.layout.fragment_chats, container, false)

        val recycler = view.findViewById<RecyclerView>(R.id.recyclerChats)
        noContactsText = view.findViewById(R.id.txtNoContacts)
        recycler.layoutManager = LinearLayoutManager(requireContext())

        adapter = ChatAdapter { message ->
            when {
                message.isGroup -> openGroupChat(message)
                message.contactId.isNotEmpty() -> {
                    val intent = Intent(requireContext(), ChatActivity::class.java)
                    intent.putExtra(ChatActivity.EXTRA_PEER_DEVICE_FINGERPRINT, message.contactId)
                    intent.putExtra(ChatActivity.EXTRA_PEER_DISPLAY_NAME, message.displayName)
                    startActivity(com.p2p.messenger.util.ShareIntake.attachTo(intent))
                    onChatOpenedFromDrawer?.invoke()
                }
            }
        }
        adapter.onContactLongClick = { message -> showChatLongPressMenu(message) }
        recycler.adapter = adapter

        // Spec dışı, kullanıcı isteği: kişi/grup adına göre arama.
        view.findViewById<SearchView>(R.id.searchChats).setOnQueryTextListener(object : SearchView.OnQueryTextListener {
            override fun onQueryTextSubmit(query: String?): Boolean = false
            override fun onQueryTextChange(newText: String?): Boolean {
                searchQuery = newText ?: ""
                applyFilter()
                return true
            }
        })

        view.findViewById<FloatingActionButton>(R.id.btnCreateGroup).setOnClickListener {
            showCreateGroupDialog()
        }

        refreshList()
        return view
    }

    private fun openGroupChat(message: ChatAdapter.ChatMessage) {
        val intent = Intent(requireContext(), GroupChatActivity::class.java)
        intent.putExtra(GroupChatActivity.EXTRA_GROUP_ID, message.contactId)
        intent.putExtra(GroupChatActivity.EXTRA_GROUP_NAME, message.displayName)
        startActivity(com.p2p.messenger.util.ShareIntake.attachTo(intent))
        onChatOpenedFromDrawer?.invoke()
    }

    /** See PinnedChatsPrefs — the same key `refreshList` used to compute
     *  `message.isPinned` for this row. */
    private fun pinKeyFor(message: ChatAdapter.ChatMessage): String =
        if (message.isGroup) "group:${message.contactId}" else message.realContactId

    private fun togglePin(message: ChatAdapter.ChatMessage) {
        val key = pinKeyFor(message)
        PinnedChatsPrefs.setPinned(requireContext(), key, !message.isPinned)
        refreshList()
    }

    /**
     * Spec dışı, uzun basma menüsü: kullanıcıyla birlikte netleştirilen iki
     * ayrı seçenek — "sohbet geçmişini temizle" (yumuşak, tek onay, kişi
     * paired kalır) ve "kişiyi sil" (sert, ÇİFT onay, eşleşme dahil her şey
     * silinir). SADECE kişiler için — gruplar `realContactId` taşımadığından
     * (bkz. ChatAdapter) bu menü zaten tetiklenmez. Ayrıca (hem kişi hem
     * grup satırları için) sohbeti sabitle/kaldır seçeneği — bkz. `togglePin`.
     */
    private fun showChatLongPressMenu(message: ChatAdapter.ChatMessage) {
        val pinLabel = getString(if (message.isPinned) R.string.action_unpin_chat else R.string.action_pin_chat)
        // Spec dışı, kullanıcı isteği: grup satırlarında DM seçenekleri
        // (geçmişi temizle/cihaz iptal/kişi sil) anlamsız — kurucuysak
        // "grubu herkes için sil" gösterilir; DİĞER üyeler için "gruptan
        // ayrıl" gösterilir (bkz. Rust `leave_group` — kurucu ayrılamaz,
        // sadece herkes için silebilir).
        if (message.isGroup) {
            val destructiveLabel = getString(
                if (message.isGroupFounder) R.string.action_delete_group else R.string.action_leave_group
            )
            AlertDialog.Builder(requireContext())
                .setTitle(message.displayName)
                .setItems(arrayOf(pinLabel, getString(R.string.action_clear_chat_history), destructiveLabel)) { _, which ->
                    when (which) {
                        0 -> togglePin(message)
                        1 -> confirmClearChatHistory(message, message.contactId)
                        2 -> if (message.isGroupFounder) confirmDeleteGroup(message) else confirmLeaveGroup(message)
                    }
                }
                .show()
            return
        }
        val options = arrayOf(
            pinLabel,
            getString(R.string.action_clear_chat_history),
            getString(R.string.action_revoke_device),
            getString(R.string.action_delete_contact)
        )
        AlertDialog.Builder(requireContext())
            .setTitle(message.displayName)
            .setItems(options) { _, which ->
                when (which) {
                    0 -> togglePin(message)
                    1 -> confirmClearChatHistory(message)
                    2 -> confirmRevokeDevice(message)
                    3 -> confirmDeleteContactStep1(message)
                }
            }
            .show()
    }

    /** Spec dışı, kullanıcı isteği: kurucu, grubu TÜM üyeler için siler
     *  (imzalı `GroupChange::Delete` herkese gider) — geri alınamaz, bu
     *  yüzden onay isteniyor (bkz. Rust `delete_group`). */
    private fun confirmDeleteGroup(message: ChatAdapter.ChatMessage) {
        AlertDialog.Builder(requireContext())
            .setMessage(R.string.confirm_delete_group)
            .setPositiveButton(R.string.action_delete_group) { _, _ ->
                offMain({
                    try { P2PLib.deleteGroup(message.contactId) } catch (e: Exception) { "Error: ${e.message}" }
                }) { result ->
                    if (result.startsWith("Error:")) {
                        Toast.makeText(requireContext(), errorText(result), Toast.LENGTH_LONG).show()
                    } else {
                        Toast.makeText(requireContext(), R.string.msg_group_deleted, Toast.LENGTH_SHORT).show()
                        refreshList()
                    }
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    /** Spec dışı, kullanıcı isteği: kurucu OLMAYAN bir üye gruptan kendi
     *  isteğiyle ayrılır (bkz. Rust `leave_group`) — geri alınamaz (tekrar
     *  katılmak için yeniden davet edilmek gerekir), bu yüzden onay
     *  isteniyor. */
    private fun confirmLeaveGroup(message: ChatAdapter.ChatMessage) {
        AlertDialog.Builder(requireContext())
            .setMessage(R.string.confirm_leave_group)
            .setPositiveButton(R.string.action_leave_group) { _, _ ->
                offMain({
                    try { P2PLib.leaveGroup(message.contactId) } catch (e: Exception) { "Error: ${e.message}" }
                }) { result ->
                    if (result.startsWith("Error:")) {
                        Toast.makeText(requireContext(), errorText(result), Toast.LENGTH_LONG).show()
                    } else {
                        Toast.makeText(requireContext(), R.string.msg_left_group, Toast.LENGTH_SHORT).show()
                        refreshList()
                    }
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    /** bkz. dosya başı notu — kişiyi/geçmişi SİLMEZ, sadece bu TEK cihazı
     *  iptal eder (bkz. Rust revoke_contact_device). Tek onay yeterli:
     *  clear-history'den daha az yıkıcı (geçmiş korunur), delete-contact'tan
     *  daha az yıkıcı (yeniden eşleşmeye gerek yok, sadece o cihaz
     *  engellenir). */
    private fun confirmRevokeDevice(message: ChatAdapter.ChatMessage) {
        if (message.contactId.isEmpty()) return
        AlertDialog.Builder(requireContext())
            .setMessage(R.string.confirm_revoke_device)
            .setPositiveButton(R.string.action_revoke_device) { _, _ ->
                offMain({
                    try { P2PLib.revokeContactDevice(message.realContactId, message.contactId) }
                    catch (e: Exception) { "Error: ${e.message}" }
                }) { result ->
                    if (result.startsWith("Error:")) {
                        Toast.makeText(requireContext(), errorText(result), Toast.LENGTH_SHORT).show()
                    } else {
                        Toast.makeText(requireContext(), R.string.msg_device_revoked, Toast.LENGTH_SHORT).show()
                        refreshList()
                    }
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun confirmClearChatHistory(message: ChatAdapter.ChatMessage, chatId: String = message.realContactId) {
        AlertDialog.Builder(requireContext())
            .setMessage(R.string.confirm_clear_chat_history)
            .setPositiveButton(R.string.action_clear_chat_history) { _, _ ->
                offMain({
                    try { P2PLib.clearChatHistory(chatId) }
                    catch (e: Exception) { "Error: ${e.message}" }
                }) { result ->
                    if (result.startsWith("Error:")) {
                        Toast.makeText(requireContext(), errorText(result), Toast.LENGTH_SHORT).show()
                    } else {
                        Toast.makeText(requireContext(), R.string.msg_chat_history_cleared, Toast.LENGTH_SHORT).show()
                        refreshList()
                    }
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    /** İlk onay — bkz. dosya başı notu, bu işlem SERT olduğundan (eşleşme
     *  dahil her şey silinir) çift onay isteniyor. */
    private fun confirmDeleteContactStep1(message: ChatAdapter.ChatMessage) {
        AlertDialog.Builder(requireContext())
            .setMessage(R.string.confirm_delete_contact_step1)
            .setPositiveButton(R.string.action_delete_contact) { _, _ -> confirmDeleteContactStep2(message) }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun confirmDeleteContactStep2(message: ChatAdapter.ChatMessage) {
        AlertDialog.Builder(requireContext())
            .setMessage(R.string.confirm_delete_contact_step2)
            .setPositiveButton(R.string.action_delete_contact) { _, _ ->
                offMain({
                    try { P2PLib.deleteContact(message.realContactId) }
                    catch (e: Exception) { "Error: ${e.message}" }
                }) { result ->
                    if (result.startsWith("Error:")) {
                        Toast.makeText(requireContext(), errorText(result), Toast.LENGTH_SHORT).show()
                    } else {
                        Toast.makeText(requireContext(), R.string.msg_contact_deleted, Toast.LENGTH_SHORT).show()
                        refreshList()
                    }
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    /** bkz. eski GroupsFragment.showCreateGroupDialog — buraya taşındı. */
    private fun showCreateGroupDialog() {
        val input = EditText(requireContext())
        input.hint = getString(R.string.lbl_new_group_name_hint)
        AlertDialog.Builder(requireContext())
            .setTitle(R.string.action_create_group)
            .setView(input)
            .setPositiveButton(R.string.action_create_group) { _, _ ->
                val name = input.text.toString().trim()
                if (name.isBlank()) return@setPositiveButton
                offMain({ P2PLib.createGroup(name) }) { groupId ->
                    if (groupId.startsWith("Error:")) {
                        Toast.makeText(requireContext(), errorText(groupId), Toast.LENGTH_LONG).show()
                    } else {
                        refreshList()
                        showAddMembersDialog(groupId)
                    }
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    /** Kişi listesinden çoklu seçimle grup üyesi ekler (bkz. spec 5.4 —
     *  kurucu davet üretir, her davet edilen mevcut/kurulmakta olan 1:1
     *  bağlantı üzerinden GroupUpdate alır). */
    private fun showAddMembersDialog(groupId: String) {
        // `listContacts` her kişinin avatarını hex olarak taşır: ana thread'de
        // çağrılmaz.
        offMain({
            try { P2PLib.listContacts() } catch (e: Exception) { "[]" }
        }) { contactsJson ->
            val array = try {
                JSONArray(contactsJson)
            } catch (e: Exception) {
                JSONArray()
            }
            if (array.length() == 0) {
                Toast.makeText(requireContext(), R.string.msg_no_contacts_to_add, Toast.LENGTH_LONG).show()
            } else {
                val names = (0 until array.length()).map {
                    array.getJSONObject(it).optString("display_name", getString(R.string.lbl_unknown))
                }.toTypedArray()
                val identityIds = (0 until array.length()).map { array.getJSONObject(it).optString("identity_id") }
                val checked = BooleanArray(names.size)

                AlertDialog.Builder(requireContext())
                    .setTitle(R.string.lbl_add_member_to_group)
                    .setMultiChoiceItems(names, checked) { _, which, isChecked -> checked[which] = isChecked }
                    .setPositiveButton(R.string.lbl_add_member_to_group) { _, _ ->
                        offMain({
                            identityIds.indices.filter { checked[it] }
                                .map { it to P2PLib.inviteToGroup(groupId, identityIds[it]) }.filter { it.second != "OK" }
                        }) { failed ->
                            for ((i, r) in failed) {
                                Toast.makeText(requireContext(), "${names[i]}: ${errorText(r)}", Toast.LENGTH_SHORT).show()
                            }
                            refreshList()
                        }
                    }
                    .setNegativeButton(android.R.string.cancel, null)
                    .show()
            }
        }
    }

    override fun onResume() {
        super.onResume()
        // Liste ekrana dönüşte ve servisten olay geldiğinde yenilenir
        // (5 saniyelik tam yeniden kurma yok — bkz. `eventListener`).
        refreshList()
        com.p2p.messenger.service.P2PService.addMessageListener(eventListener)
        // 300 ms: the service flips out of power save on the same resume.
        refreshHandler.postDelayed(syncRunnable, 300)
    }

    override fun onPause() {
        super.onPause()
        com.p2p.messenger.service.P2PService.removeMessageListener(eventListener)
        refreshHandler.removeCallbacks(eventRefreshRunnable)
        eventRefreshQueued = false
        refreshHandler.removeCallbacks(syncRunnable)
    }

    /** Görünüm yok edilince avatar baytları da bırakılır: `allChatItems`
     *  her kişi/grubun TAM avatarını (100-250 KB) tutuyordu ve liste
     *  başka bir sekmede açıkken de bellekte kalıyordu. */
    override fun onDestroyView() {
        super.onDestroyView()
        refreshHandler.removeCallbacksAndMessages(null)
        allChatItems = emptyList()
        if (::adapter.isInitialized) adapter.submitList(emptyList())
    }

    override fun onDestroy() {
        super.onDestroy()
        // The worker is a live non-daemon thread: shut it down with the
        // fragment.
        worker.shutdownNow()
    }

    /** JNI calls that take the core lock, off the main thread; [done] runs on
     *  the main thread while the fragment is still attached. */
    private val worker = java.util.concurrent.Executors.newSingleThreadExecutor()

    /** Runs [work] on the worker thread; the executor is gone after
     *  `onDestroy` (a late callback must not crash the app). */
    private fun runOnWorker(work: () -> Unit) {
        try {
            worker.execute(work)
        } catch (e: java.util.concurrent.RejectedExecutionException) {
            // Fragment yok — sonuç zaten gösterecek bir ekran da yok.
        }
    }

    private fun <T> offMain(work: () -> T, done: (T) -> Unit) {
        runOnWorker {
            // A detached fragment throws from getString: drop the result.
            val result = try { work() } catch (e: Exception) { return@runOnWorker }
            refreshHandler.post { if (isAdded && view != null) done(result) }
        }
    }

    @Volatile private var refreshing = false
    /** A refresh was asked for while one was running (after a delete, a
     *  pin...): run once more, the running one may have read the old state. */
    @Volatile private var refreshAgain = false

    /** Rebuilds the whole list: one history query and the whole attachment
     *  list per chat, under the core lock. On the main thread that was
     *  stutter, and an ANR behind a long poll turn.
     *  Runs when the screen comes back and when the service reports an event
     *  — NOT every 5 s (that was the cost this list had in every open chat
     *  and in every chat screen's drawer). */
    private fun refreshList() {
        if (refreshing) { refreshAgain = true; return }
        val ctx = context?.applicationContext ?: return
        refreshing = true
        runOnWorker {
            val result = try { buildChatItems(ctx) } catch (e: Exception) { null }
            refreshHandler.post {
                refreshing = false
                if (refreshAgain) { refreshAgain = false; refreshList() }
                if (result == null || !isAdded || view == null) return@post
                noContactsText.visibility = if (result.isEmpty()) View.VISIBLE else View.GONE
                allChatItems = result
                applyFilter()
            }
        }
    }

    private fun buildChatItems(ctx: android.content.Context): List<ChatAdapter.ChatMessage> {
        val contacts = loadContacts(ctx)
        val groups = loadGroups()
        val previews = try { JSONObject(P2PLib.chatListPreviews()) } catch (e: Exception) { null }

        val duplicateNames = com.p2p.messenger.util.ContactNames.duplicates(contacts.map { it.displayName })
        val contactItems = contacts.map { contact ->
            val fingerprint = contact.activeDeviceFingerprint ?: ""
            // Spec dışı, kullanıcı isteği: son satır SADECE metin mesajı
            // değil, EK de olabilir — ikisinden hangisi daha yeniyse o
            // gösterilir (ekler `messages` tablosunda değil `files`
            // tablosunda tutulduğu için ayrı sorgulanır).
            val lastMessage = if (fingerprint.isNotEmpty()) previewOf(previews?.optJSONObject("contacts")?.optJSONObject(contact.identityId)) else null
            ChatAdapter.ChatMessage(
                contactId = fingerprint,
                displayName = com.p2p.messenger.util.ContactNames.label(contact.displayName, contact.identityId, duplicateNames),
                lastMessage = lastMessage?.text ?: "",
                timestamp = lastMessage?.timestamp ?: 0L,
                hasUnread = lastMessage != null &&
                    lastMessage.timestamp > ReadStatePrefs.lastReadAtForContact(ctx, contact.contactId, fingerprint),
                // Keyed on the STABLE contact id (not the device fingerprint,
                // which can change if the contact re-pairs a device) so a
                // pin survives that.
                isPinned = PinnedChatsPrefs.isPinned(ctx, contact.contactId),
                realContactId = contact.contactId,
                avatarJpeg = contact.avatarHex?.let { hexToBytes(it) }
            )
        }
        val groupItems = groups.map { group ->
            // Spec dışı, kullanıcı isteği: gruplar için de gerçek son mesaj/ek
            // önizlemesi (1:1 kişilerle AYNI mantık) — hem sohbet listesinin
            // "en güncel mesaj atılan en üstte" sıralanabilmesi için gerçek
            // bir zaman damgası gerektiğinden, hem de sabit "N üye" metninin
            // hiçbir zaman değişmeyen, bilgi vermeyen bir önizleme olmasından.
            val lastMessage = previewOf(previews?.optJSONObject("groups")?.optJSONObject(group.groupId))
            ChatAdapter.ChatMessage(
                contactId = group.groupId,
                displayName = group.name,
                lastMessage = lastMessage?.text
                    ?: resources.getQuantityString(R.plurals.lbl_member_count, group.memberCount, group.memberCount),
                timestamp = lastMessage?.timestamp ?: 0L,
                hasUnread = lastMessage != null &&
                    lastMessage.timestamp > ReadStatePrefs.lastReadAt(ctx, "group:${group.groupId}"),
                isPinned = PinnedChatsPrefs.isPinned(ctx, "group:${group.groupId}"),
                avatarJpeg = group.avatarHex?.let { hexToBytes(it) },
                isGroup = true,
                isGroupFounder = group.isFounder
            )
        }
        // Spec dışı, kullanıcı isteği: sohbet listesi en güncel mesaj
        // atılan/alınan en üstte olacak şekilde sıralanır (hem kişiler hem
        // gruplar, tek bir zaman çizelgesinde). Hiç mesajı olmayan bir
        // sohbet (timestamp=0) listenin EN ALTINDA kalır — azalan sıralamada
        // doğal olarak en son sıraya düşer. Pinlenmiş sohbetler (birden
        // çok olabilir) bu sıralamanın ÜZERİNDE, kendi aralarında yine en
        // güncel mesaja göre en üstte durur.
        return (contactItems + groupItems)
            .sortedWith(compareByDescending<ChatAdapter.ChatMessage> { it.isPinned }.thenByDescending { it.timestamp })
    }

    /** bkz. `allChatItems`/`searchQuery` dosya başı notu — kişi/grup adına
     *  (uyarı işareti/baş harf rozeti gibi süslemeler hariç, ham
     *  `displayName` üzerinden) büyük/küçük harf duyarsız arama. */
    private fun applyFilter() {
        val query = searchQuery.trim()
        val filtered = if (query.isEmpty()) {
            allChatItems
        } else {
            allChatItems.filter { it.displayName.contains(query, ignoreCase = true) }
        }
        adapter.submitList(filtered) { adapter.refreshTimeLabels() }
    }

    private data class ContactRow(
        val contactId: String,
        val displayName: String,
        val identityId: String,
        val activeDeviceFingerprint: String?,
        val avatarHex: String?
    )
    private data class GroupRow(val groupId: String, val name: String, val memberCount: Int, val avatarHex: String?, val isFounder: Boolean)
    private data class LastMessagePreview(val text: String, val timestamp: Long)

    /** H137: the newer of the last text row and the last attachment (one
     *  `chatListPreviews` call for the whole list instead of two per chat). */
    private fun previewOf(entry: JSONObject?): LastMessagePreview? {
        if (entry == null) return null
        val m = entry.optJSONObject("message")
        val a = entry.optJSONObject("attachment")
        val msg = m?.let {
            // A deleted row shows the placeholder, as the bubble does.
            LastMessagePreview(
                if (it.optBoolean("is_deleted", false)) getString(R.string.msg_deleted) else it.optString("text", ""),
                it.optLong("timestamp", 0L)
            )
        }
        val att = a?.let {
            LastMessagePreview(attachmentPreviewLabel(it.optString("mime_type", ""), it.optString("file_name", ""), it.optBoolean("sticker")), it.optLong("created_at", 0L))
        }
        return when {
            msg == null -> att
            att == null -> msg
            att.timestamp > msg.timestamp -> att
            else -> msg
        }
    }

    /** Ek türüne göre kısa etiket — bilinmeyen türlerde dosya adı. */
    private fun attachmentPreviewLabel(mimeType: String, fileName: String, sticker: Boolean): String = when {
        sticker -> getString(R.string.lbl_last_sticker)
        mimeType.startsWith("image/") -> getString(R.string.lbl_last_photo)
        mimeType.startsWith("video/") -> getString(R.string.lbl_last_video)
        mimeType.startsWith("audio/") -> getString(R.string.lbl_last_voice)
        fileName.isNotEmpty() -> "📎 $fileName"
        else -> getString(R.string.lbl_last_file)
    }

    private fun loadContacts(ctx: android.content.Context): List<ContactRow> {
        val json = try {
            P2PLib.listContacts()
        } catch (e: Exception) {
            return emptyList()
        }
        val array = try {
            JSONArray(json)
        } catch (e: Exception) {
            return emptyList()
        }
        return (0 until array.length()).map { i ->
            val obj = array.getJSONObject(i)
            val fingerprint = if (obj.isNull("active_device_fingerprint")) null
                else obj.optString("active_device_fingerprint")
            ContactRow(
                contactId = obj.optString("contact_id"),
                // The fallback is the same in both tabs (it used to be
                // "Bilinmeyen" here and "Unknown" in the contacts tab).
                displayName = obj.optString("display_name", ctx.getString(R.string.lbl_unknown)),
                identityId = obj.optString("identity_id"),
                activeDeviceFingerprint = fingerprint,
                avatarHex = if (obj.isNull("avatar_hex")) null else obj.optString("avatar_hex").ifEmpty { null }
            )
        }
    }

    private fun loadGroups(): List<GroupRow> {
        val json = try {
            P2PLib.listGroups()
        } catch (e: Exception) {
            return emptyList()
        }
        val array = try {
            JSONArray(json)
        } catch (e: Exception) {
            return emptyList()
        }
        return (0 until array.length()).map { i ->
            val obj = array.getJSONObject(i)
            val members = obj.optJSONArray("member_identity_ids")
            GroupRow(
                groupId = obj.optString("group_id"),
                name = obj.optString("name"),
                memberCount = members?.length() ?: 0,
                avatarHex = if (obj.isNull("avatar_hex")) null else obj.optString("avatar_hex").ifEmpty { null },
                // Spec dışı, kullanıcı isteği: "grubu herkes için sil"
                // seçeneği yalnızca kurucuya gösterilir.
                isFounder = obj.optBoolean("is_founder", false)
            )
        }
    }
}
