package com.p2p.messenger

object P2PLib {
    init {
        System.loadLibrary("p2p_messenger")
        if (BuildConfig.DEBUG) enableLogging()
    }

    /** Logcat output of the core and arti; never called in a release. */
    private external fun enableLogging()

    // --- Section 1: Identity and device ---
    /** Opens the SQLite database in the app's private files directory (Context.filesDir.absolutePath). Must be called before anything else.
     *  If an identity is stored, its public keys are also loaded into memory. */
    fun initDatabase(filesDir: String): Boolean {
        if (databaseOpen) return true
        // Its key is sealed with the vault key: closed until the app password is entered.
        if (!com.p2p.messenger.util.Vault.isOpen()) return false
        return com.p2p.messenger.util.SkippedKeyManager.openDatabase(java.io.File(filesDir)).also { databaseOpen = it }
    }
    @Volatile private var databaseOpen = false
    /** The database is encrypted under [storageKey] (the SkippedKeyManager
     *  key). Only through [initDatabase]. */
    external fun initDatabaseKeyed(filesDir: String, storageKey: ByteArray): Boolean
    /** After initDatabase: whether an identity is already stored in the DB (its public key records are loaded into memory). */
    external fun hasStoredIdentity(): Boolean
    /** Creates a new identity and its first device. Returns identity_id, or "Error: ...".
     *  Right after this call, getPendingSecretBundle() must be called, and the result encrypted with KeystoreCrypto and stored. Otherwise the secret keys
     *  exist only in memory and are lost when the process dies. */
    external fun createIdentity(deviceName: String): String
    /** Called once after createIdentity: returns the secret key bundle just generated (CBOR, plaintext). It stays in memory on the Rust side, so a failed
     *  disk write can be retried. It is cleared by loadSecretBundle and by wipe_all_local_state
     *  (device revoke or local wipe), and replaced when createIdentity or importRecovery generates a new bundle. */
    external fun getPendingSecretBundle(): ByteArray
    /** Loads a secret bundle, decrypted by the Keystore, into memory. Called at app start, after initDatabase, once hasStoredIdentity is true. */
    external fun loadSecretBundle(bundleBytes: ByteArray): Boolean
    external fun getIdentityCode(): String
    external fun getIdentityShortCode(): String
    /** Group reply labels: when the replied-to message is not loaded locally, this decides whether to show "You" or a member's name.
     *  Unlike getIdentityCode / getIdentityShortCode, this returns the RAW hex identity_id, not a formatted one. It has the same form as the
     *  sender_identity_id and reply_to_sender_identity_id fields, so they compare directly. */
    external fun getOwnIdentityId(): String

    // --- Section 4: Network ---
    /** `torEnabled`: when on, a Tor onion service is started with arti, so the device is reachable even behind CGNAT (see tor.rs and SECURITY.md).
     *  Tor status is monitored with `torStatus()`. Changing this setting requires restarting the network layer (a transport cannot be added to a live swarm). */
    external fun startNetwork(nodeMode: Boolean, torEnabled: Boolean): String
    external fun setNodeMode(enabled: Boolean)
    /** Tor connection for the next `startNetwork`: mode "direct" / "snowflake" / "obfs4" (+ bridge lines). `ptDir` = nativeLibraryDir. "OK" or "Error: ...". */
    external fun setTorTransport(mode: String, bridges: String, ptDir: String): String
    /** "OK", or "Error: line N: ..." for the first bad obfs4 bridge line. */
    external fun validateBridgeLines(text: String): String
    /** The PT binary for [mode] ships in this APK (liblyrebird.so in [ptDir]: obfs4 + snowflake). */
    external fun torTransportAvailable(mode: String, ptDir: String): Boolean
    /** The history and attachment storage limit slider (100 MB to 32 GB) in Settings. It applies only while node mode is on (see Rust
     *  `enforce_history_storage_limit`). Lowering the limit deletes the oldest files at once. */
    external fun setHistoryStorageLimitBytes(bytes: Long)
    /** Tor status for the UI. Returns "disabled", "bootstrapping", "ready", "ready|<host>.onion", or "failed". */
    external fun torStatus(): String
    /** Self-update check (update.rs). Blocking, network. Verified APK path, "" if nothing to do, or "Error: ...". */
    external fun checkUpdate(dir: String, current: String, force: Boolean): String
    /** The general network status of THIS device (not the peer's; see hasActiveSession and isPeerConnected). JSON:
     *  {"connected_peers": Int, "listening": Bool, "tor_enabled": Bool, "tor_status": String, "node_mode": Bool}. Shown in the chat screen's top bar. */
    external fun ownConnectionStatus(): String
    /** Polls the network; returns any messages decrypted during this poll. */
    external fun pollNetwork(): Array<String>
    /** The onion address the other side can dial (`/dns/<host>.onion/tcp/<port>/p2p/<peer_id>`). The rendezvous_node of the QR and manual
     *  pairing flow must be this. It is an empty string while the onion service is not published yet (Tor bootstrapping); a LAN or listen address is never returned. */
    external fun getNodeAddress(): String

    // --- Sections 1.3 and 1.4: QR and manual pairing ---
    external fun generateQrPacket(rendezvousNode: String): ByteArray
    /** Produces the `identity_id|device_fingerprint|nonce|device_name|rendezvous_node` format that processManualEntry expects, so it can be copied to the
     *  clipboard and sent to the other side (for example by screen share or message, if they are on a different network). Returns "" on error. */
    external fun getManualAddCode(rendezvousNode: String): String
    /** Returns `{"identity_id":...,"device_fingerprint":...,"device_name":...}` (JSON) on success, or "Error: ..." on failure.
     *  `device_fingerprint` lets the caller (see QrScanActivity) open the new contact's chat screen directly, and show that pairing is still in progress
     *  ("Connecting..."). It does NOT wait for `active_device_fingerprint` from listContacts(), which is filled only once the real IdentityExchange completes. */
    external fun processQrPacket(data: ByteArray): String
    /** See the same return-format note in `processQrPacket`. */
    external fun processManualEntry(text: String): String
    /** JSON-encoded List<ContactSummary>. */
    external fun listContacts(): String

    // --- Multi-device (sections 1.5, 1.6, 1.7): binding a secondary device ---
    /** On the secondary (new) device: the raw CBOR bytes of the 'add device' QR that binds this device to an identity. This device must first have gone through
     *  the normal `createIdentity` and `startNetwork` (so it has a provisional identity). It can return empty until `getNodeAddress()` is ready. */
    external fun buildDeviceLinkRequest(): ByteArray

    /** Closes the window in which a link grant is accepted (QR screen left). */
    external fun closeDeviceLinkWindow()
    /** On the primary (existing account) device: processes a scanned secondary device QR (CBOR). It approves and binds the device, sends a full sync, and announces
     *  the new device to all contacts. Returns `{"device_fingerprint":...,"device_name":...}` on success, otherwise "Error: ...". */
    external fun approveDeviceLink(data: ByteArray): String
    /** Reads a scanned link QR without acting on it. Same return shape. */
    external fun peekDeviceLink(data: ByteArray): String
    /** Six-digit compare code of a link QR ("123 456"): the new device and the
     *  approving device both show it. Empty if [data] is not a link request. */
    external fun deviceLinkCode(data: ByteArray): String
    /** The devices of my identity (this device plus linked sibling devices). JSON array: [{"device_fingerprint","device_name","is_active","is_this_device"}]. */
    external fun listLinkedDevices(): String
    /** Whether THIS device was linked to an identity as a SECONDARY device (approved by another device). The secondary device's linking QR screen uses this
     *  to know that linking is complete. */
    external fun isSecondaryDevice(): Boolean
    /** Revokes a sibling device (section 1.6): a signed revocation spreads to all contacts and siblings. Returns "OK" or "Error: ...". */
    external fun revokeLinkedDevice(deviceFingerprint: String): String
    /** Hides a revoked sibling from [listLinkedDevices]. */
    external fun forgetRevokedLinkedDevice(deviceFingerprint: String): String
    /** Multi-device (section 1.7.1): when a chat is read on THIS device, the sibling devices are told it was read (so they count it as read too). For 1:1, `peerDeviceFingerprint`
     *  is set and `groupId` is empty; for a group, the reverse. No-op if there is no sibling device. It reaches the other devices as a "read_state_sync" pollNetwork event. */
    external fun syncReadState(peerDeviceFingerprint: String, groupId: String, readAtMs: Long)
    /** Disappearing messages on screen start counting down in the core too. Local only, nothing is sent. */
    external fun startDisappearCountdown(peerDeviceFingerprint: String, groupId: String)
    /** The chat's disappearing mode in seconds, 0 = off. Every message sent in the chat carries it (text, files, voice, stickers). */
    external fun getDisappearMode(peerDeviceFingerprint: String, groupId: String): Long
    external fun setDisappearMode(peerDeviceFingerprint: String, groupId: String, secs: Long)

    // --- Section 2.2: device change alerts ---
    /** JSON-encoded List<DeviceAlertInfo>. */
    external fun listPendingDeviceAlerts(): String
    external fun acceptDeviceAlert(fingerprint: String): Boolean
    external fun rejectDeviceAlert(fingerprint: String)

    /**
     * Blocks a contact. This differs from `revokeContactDevice` on purpose: revoke shuts down ONE device, and the person can come back with a new device.
     * A block targets the IDENTITY: no packet from any of their devices is accepted, no connection is made to any of them, and not even a 'new device' alert is raised.
     * A block is lifted by [unblockIdentity] on the user's explicit request, or by a face-to-face re-pairing (QR or manual code).
     */
    external fun blockIdentity(identityId: String): String

    /** Lifts a block. Call only on the user's explicit request. */
    external fun unblockIdentity(identityId: String)

    /** Engellenen kimlikler, JSON dizisi. */
    external fun listBlockedIdentities(): String

    /**
     * Power-save mode (battery design, see P2PService).
     *
     * It is entered when the screen is off AND the app is in the background. It does not change network behaviour: it only lengthens the liveness-check
     * interval of connections that are already healthy and quiet, from 20 s to 60 s. The main gain is the cellular radio, which stays at high power for 5-15 s
     * after each check.
     */
    external fun setPowerSave(enabled: Boolean)

    /**
     * A contact's SAFETY CODE, which is what gets compared when the user marks a contact as verified.
     *
     * The code is derived from the contact's device fingerprint, and that fingerprint is a digest of four public keys. A matching code on both sides means both
     * really saw the same keys. For contacts met through a group, the keys come from the founder. There is NO cryptographic way to rule out a malicious founder
     * in that case; only comparing this code over another channel (a phone call, in person) does.
     */
    external fun contactSafetyCode(identityId: String): String

    /**
     * Gives FULL trust to a contact met through a group: removes the "added via group, not verified" mark in the UI. The encryption was already the same;
     * this only changes the trust indicator.
     */
    external fun trustContact(contactId: String): String

    /**
     * Hands the group founder role to another MEMBER. If the founder loses all devices, the group would otherwise be locked for good.
     */
    external fun transferGroupFounder(groupId: String, newFounderIdentityId: String): String

    /** Founder only: re-sends the current signed group state to each member device. Returns "OK" or "Error: ...". */
    external fun resendGroupToAll(groupId: String): String

    // --- Pending messages (not yet acknowledged) ---
    //     See `awaiting_confirmation` in the Rust core, the `regen_content` extension in types.rs, and the SettingsFragment "Pending Messages" screen.
    /** Called when the app comes to the foreground (see P2PApplication's foreground detection and network.rs `retry_all_pending_now`). It retries at once,
     *  without waiting for the exponential back-off interval. */
    external fun retryAllPendingNow()
    /** JSON-encoded List<PendingMessageSummary>. */
    external fun listPendingMessages(): String
    /** Permanently drops a pending message (it becomes Failed). See network.rs `cancel_pending_message`. */
    external fun cancelPendingMessage(messageId: String): Boolean
    /** The manual "Retry now" button in the pending messages list. See network.rs `retry_pending_message_now`. It only moves this message's next retry time to NOW;
     *  no network I/O happens here. */
    external fun retryPendingMessageNow(messageId: String): Boolean

    // --- Network reconnect after a change of network ---
    /** Poll thread: blocks until a network event happens, another call needs the core, or `timeoutMs` elapses (see Rust `wait_for_network_activity`).
     *  It replaces a fixed `postDelayed` wait, so messages do not wait for a poll turn. */
    external fun waitForNetworkActivity(timeoutMs: Long)

    /** Ends a running [waitForNetworkActivity] at once. Takes no core lock. */
    external fun wakePoll()
    /** Argon2id key (32 bytes) of the app password, see [com.p2p.messenger.util.Vault]. Empty on bad input. Does not take the core lock. */
    external fun argon2idKey(password: String, salt: ByteArray, mKib: Int, t: Int): ByteArray
    /** Release builds, at start: the process is not dumpable (no same-uid ptrace, no core dump). */
    external fun hardenProcess()
    /** Debugger or hooking tools (Frida, Xposed, Substrate) inside this process, comma separated; empty when none. See [com.p2p.messenger.util.Vault.checkTamper]. */
    external fun tamperSigns(): String
    /** Reports a network interface change (Wi-Fi and cellular switch, or the network disappearing and coming back). See P2PService
     *  `observeNetworkChangesForReconnect` and session.rs `reconnect_all_known_now`. For ALL known active devices, it tries to reconnect at once,
     *  ignoring the back-off history. */
    external fun notifyNetworkChanged()

    // --- Section 3: Messaging ---
    /** Returns `{"message_id":"...","status":"sent"|"pending"}` (JSON) on success, or "Error: ...". `status` lets the message bubble show the right send icon at once.
     *  If it is "pending", the message is retried automatically in the background, and a "status" event (pollNetwork) updates it. */
    /** `replyToMessageId` and `replyToPreview` are for swipe-to-reply. If there is no reply, both must be passed as `null`: default parameter values are not used
     *  on `external fun`, so every caller passes `null` explicitly. `replyToPreview` is a short summary of the replied-to message (truncated
     *  by the caller), so the receiver can show the reply without looking in its own archive. */
    /** `expireSecs`: a disappearing message (seconds after it is read), 0 = an ordinary one. See ui/Disappear.kt. */
    external fun sendMessage(targetDeviceFingerprint: String, message: String, replyToMessageId: String?, replyToPreview: String?, expireSecs: Long): String
    /** Returns the same JSON format as sendMessage. */
    external fun editMessage(targetDeviceFingerprint: String, targetMessageId: String, newText: String): String
    external fun deleteMessage(targetDeviceFingerprint: String, targetMessageId: String): String
    /** Places an emoji reaction on a message. An EMPTY `emoji` removes my own reaction (there is no separate remove call: one reaction per person, see Rust
     *  `MessageContent::Reaction`). Returns the message's CURRENT reaction summary (for example "👍2 ❤️"), which can be written straight into the reaction pill. */
    external fun reactToMessage(targetDeviceFingerprint: String, targetMessageId: String, emoji: String): String
    /** Group counterpart of `reactToMessage`. */
    external fun reactToGroupMessage(groupId: String, targetMessageId: String, emoji: String): String
    /** Returns the "who reacted with what" list, shown when the reaction pill is tapped. JSON: [{"identity_id":"...","emoji":"👍"}, ...], newest reaction first.
     *  The summary on the pill (see the return of `reactToMessage`) carries only totals and no person information, so this is a separate call. */
    external fun listReactions(targetMessageId: String): String
    /** Who has seen a message and when: [{"identity_id":"...","seen_at_ms":123}, ...], first viewer first. */
    external fun listSeenBy(messageId: String): String
    /** My 5 most used reaction emojis, for the double-tap quick-reaction bar. JSON string array, padded with defaults. */
    external fun topReactions(): String
    /** Group counterpart of `editMessage` and `deleteMessage`: it is sent to ALL reachable other members (the same fan-out pattern as `sendGroupMessage`).
     *  `targetGroupMessageLocalId` is the `messageId` of the group message to edit or delete (the `group_message_local_id` returned when it was sent).
     *  Returns "OK" or "Error: ...". */
    external fun editGroupMessage(groupId: String, targetGroupMessageLocalId: String, newText: String): String
    external fun deleteGroupMessage(groupId: String, targetGroupMessageLocalId: String): String
    /** Whether an active ratchet session with a counterpart exists (the handshake has completed). Used for the 'Connecting...' indicator of ChatActivity. */
    external fun hasActiveSession(peerDeviceFingerprint: String): Boolean
    /** The REAL live connection state. Unlike `hasActiveSession` (which checks whether a ratchet session was set up, and stays true for good once it was),
     *  this asks the swarm's own connection book whether the peer is connected RIGHT NOW. Use it for the 'Connected' / 'Connecting' status text on the chat screen.
     *  The 'Connecting...' banner (first handshake) still uses hasActiveSession. These are different questions. */
    external fun isPeerConnected(peerDeviceFingerprint: String): Boolean
    /** Starts the handshake proactively when a chat opens (a no-op if a session already exists). */
    external fun ensureHandshake(peerDeviceFingerprint: String)
    /** A "seen" notice: the same pattern as `Ack`, but NOT automatic. The UI must call it at the moment the message is actually shown on screen.
     *  `groupMessageLocalId`: null in a 1:1 chat. In a group chat, the same value from the "group_message" event must be sent back (see the Rust packet.rs `Seen` note). */
    external fun sendSeenReceipt(targetDeviceFingerprint: String, targetMessageId: String, groupMessageLocalId: String?): Boolean

    // --- Message history (encrypted local archive, kept on every device) ---
    /** Loads the 32-byte history encryption key, unwrapped from the Keystore. */
    external fun setHistoryKey(keyBytes: ByteArray): Boolean
    /** Loads the key that encrypts the skipped-message-key cache on disk. It must be called regardless of node mode. See the Rust setSkippedKeyEncryptionKey docs. */
    external fun setSkippedKeyEncryptionKey(keyBytes: ByteArray): Boolean
    /** JSON-encoded List<ArchivedMessage>, oldest to newest. Each item now also has `message_id` and `status` fields (see the Rust ArchivedMessage note on status persistence). */
    external fun getMessageHistory(peerDeviceFingerprint: String, limit: Int): String
    /** Group counterpart of `getMessageHistory`. It must be called when GroupChatActivity opens. Without it the screen would always start empty.
     *  Each item also has `sender_identity_id`, since a group can have several senders. */
    external fun getGroupMessageHistory(groupId: String, limit: Int): String
    /** If the local history is empty on a device with node mode off, sends an encrypted history request to the other side (if node mode is on there).
     *  The reply arrives asynchronously; see the pollNetwork "history_sync" event. */
    external fun requestHistorySync(peerDeviceFingerprint: String, limit: Int)
    /** Chat open: the newest rows of this chat from my other devices. `chatKey`: peer device fingerprint or group id. */
    external fun refreshChatFromSiblings(chatKey: String, isGroup: Boolean)
    /** When the chat history is scrolled to the top, THIS must be called first. If the LOCAL archive has messages older than `beforeTimestamp`, it returns them
     *  (without needing the network), in the same JSON format as `getMessageHistory`. */
    external fun getMessageHistoryBefore(peerDeviceFingerprint: String, beforeTimestamp: Long, limit: Int): String
    /** Group counterpart of `getMessageHistoryBefore`, for the group archive. */
    external fun getGroupMessageHistoryBefore(groupId: String, beforeTimestamp: Long, limit: Int): String
    /** only rows archived after `afterTimestamp`, oldest first; same JSON as `getMessageHistory`. */
    external fun getMessageHistorySince(peerDeviceFingerprint: String, afterTimestamp: Long, limit: Int): String
    external fun getGroupMessageHistorySince(groupId: String, afterTimestamp: Long, limit: Int): String
    /** `{"contacts":{identity_id:{"peer","message","attachment"}},"groups":{gid:{"message","attachment"}}}`;
     *  message / attachment may be null (message.timestamp, attachment.created_at). */
    external fun chatListPreviews(): String

    // --- File, photo, video and audio attachments (up to 4 GB) ---
    /** `sourcePath` must already be a local file path (NOT a content:// URI: the caller first copies it to a local cache file with ContentResolver).
     *  `previewJpeg`: for photo and video attachments, a small 480p / 85% JPEG cover made beforehand (see ChatActivity generateImagePreview and
     *  generateVideoPreview). Pass `null` for other types. Large files can take a while: do NOT call on the main thread (use coroutines and Dispatchers.IO).
     *  Returns the same JSON format as sendMessage, with the `message_id` field carrying the file_id here. */
    /** `durationMs`: the playback length for voice messages. Pass -1 for other types (a JNI int cannot carry null, so -1 means "none"). */
    external fun prepareAndSendFile(targetDeviceFingerprint: String, sourcePath: String, fileName: String, mimeType: String, previewJpeg: ByteArray?, durationMs: Int, caption: String, replyToMessageId: String, replyToPreview: String): String
    /** On success returns "OK". Progress and completion then arrive through pollNetwork as "file_progress", "file_complete" and "file_failed" events.
     *  On failure it returns "Error: ...", and in that case NO pollNetwork event will come (the download never started). The caller MUST check this return value,
     *  or the UI stays stuck on 'Downloading' forever. */
    external fun downloadFile(fileId: String, peerDeviceFingerprint: String): String
    /** JSON-encoded List<AttachmentSummary>, in creation order. */
    external fun listAttachments(peerDeviceFingerprint: String): String

    /** [listAttachments] rows older than [beforeMs] (created_at), oldest first. */
    external fun listAttachmentsBefore(peerDeviceFingerprint: String, beforeMs: Long, limit: Int): String
    external fun listGroupAttachmentsBefore(groupId: String, beforeMs: Long, limit: Int): String

    /** [listAttachments] / [listGroupAttachments] without the preview images. */
    external fun listAttachmentsBrief(peerDeviceFingerprint: String): String
    external fun listGroupAttachmentsBrief(groupId: String): String
    /** Group counterpart of `prepareAndSendFile`: the file is encrypted ONCE and offered to ALL reachable other members with the same `file_id` and key.
     *  Returns `file_id` on success, otherwise "Error: ...". There is no separate download function for groups: the existing `downloadFile` is used
     *  (the `peer_device_fingerprint` in `listGroupAttachments` results names the sender to download from). */
    external fun prepareAndSendGroupFile(groupId: String, sourcePath: String, fileName: String, mimeType: String, previewJpeg: ByteArray?, durationMs: Int, caption: String, replyToMessageId: String, replyToPreview: String, replyToSenderIdentityId: String): String
    /** See `listAttachments`, for group attachments. Each item also has `peer_device_fingerprint` (which sender `downloadFile` asks) and
     *  `sender_identity_id` (who sent it, for the name and avatar display). */
    external fun listGroupAttachments(groupId: String): String

    // --- Stickers ---
    /** Creates and stores a sticker from RGBA frames (not premultiplied). The longest side should be 600 px; scaling is done on the Kotlin side.
     *  One frame makes a still sticker. Returns the sticker id, or "Error: ...". */
    external fun importStickerFrames(frames: Array<ByteArray>, width: Int, height: Int, delaysMs: IntArray, origin: String?): String
    /** JSON: [{"id","animated","created_at"}], newest first. */
    external fun listStickers(): String
    /** A displayable copy of a sticker: the ABSOLUTE path of its `.png` (still) or `.gif` (animated) file, or "Error: ...". */
    external fun stickerPlainPath(id: String): String
    /** First frame of a sticker as a PNG path (fast placeholder), or "Error: ...". */
    external fun stickerFirstFrame(id: String): String
    /** First frame of a JPEG XL attachment as a PNG path, or "Error: ...". */
    external fun getAttachmentFirstFrame(fileId: String): String
    /** Whether the store has a sticker with this source id (`wa:` or `jxl:`). */
    external fun hasStickerOrigin(origin: String): Boolean
    /** Deletes a sticker from its own store. "OK" or "Error: ...". */
    external fun deleteSticker(id: String): String
    /** Deletes several stickers ([idsJson]: JSON array of ids), one sync echo. "OK" or "Error: ...". */
    external fun deleteStickers(idsJson: String): String
    external fun setStickerFavorite(id: String, favorite: Boolean): String
    /** This device's sticker folders: JSON [{"id","name","stickers":[sticker id]}], oldest first. */
    external fun listStickerFolders(): String
    /** Returns the new folder's id, or "Error: ...". */
    external fun createStickerFolder(name: String): String
    external fun renameStickerFolder(id: Long, name: String): String
    /** Deletes the folder only; its stickers stay. "OK" or "Error: ...". */
    external fun deleteStickerFolder(id: Long): String
    /** [idsJson]: JSON array of sticker ids. "OK" or "Error: ...". */
    external fun addStickersToFolder(id: Long, idsJson: String): String
    /** Takes stickers out of a folder; they stay in the store. "OK" or "Error: ...". */
    external fun removeStickersFromFolder(id: Long, idsJson: String): String
    /** Sends a sticker to a contact's device. Returns the attachment's `file_id`, or "Error: ...". */
    external fun sendSticker(peerFp: String, stickerId: String, replyToMessageId: String, replyToPreview: String): String
    /** Group counterpart of `sendSticker`. */
    external fun sendGroupSticker(groupId: String, stickerId: String, replyToMessageId: String, replyToPreview: String, replyToSenderIdentityId: String): String
    /** Copies a received (downloaded) sticker into this device's own sticker store. Returns the sticker id, or "Error: ...". */
    external fun saveReceivedSticker(fileId: String): String

    // --- Settings → Storage ---
    /** JSON: `{"db_bytes","attachments_bytes","voice_bytes","stickers_bytes",
     *  "cache_bytes","chats":[{"kind":"contact"|"group","id","name","bytes","count"}]}`;
     *  `chats`: only chats with local attachments, biggest first. */
    external fun storageUsage(): String
    /** JSON `{"oldest_ms","msg_count","msg_bytes","del_msg_count","del_msg_bytes",
     *  "att_bytes","del_att_bytes"}` for deleting a chat's items older than [beforeMs]. */
    external fun chatPruneStats(kind: String, id: String, beforeMs: Long): String
    /** Deletes a chat's messages and attachments older than [beforeMs] (this device only). "OK" or "Error: ...". */
    external fun pruneChatBefore(kind: String, id: String, beforeMs: Long): String
    /** Drops only this device's copy of each `file_id` (JSON array); the row
     *  stays, downloadable again; the peer is not told. "OK" or "Error: ...". */
    external fun removeLocalAttachments(fileIdsJson: String): String
    /** The ABSOLUTE path of the decrypted (plaintext) copy of a completed attachment, or "Error: ..." on error. For LARGE files, do NOT call this on the main thread. */
    external fun getAttachmentPlaintextPath(fileId: String): String
    /** A JPEG XL attachment as it came (no PNG/GIF conversion), for "Save as JPEG XL". Path or "Error: ...". */
    external fun getAttachmentOriginalPath(fileId: String): String
    /** Lossless JPEG XL of [pixels] (direct buffer, `width * height` RGBA,
     *  not premultiplied; changed by the call) to [outPath]. "OK" or "Error: ...". */
    external fun encodeJxlLossless(bitmap: android.graphics.Bitmap, hasAlpha: Boolean, outPath: String): String

    /** Animated lossless JPEG XL; [frames] = full-canvas RGBA (<= 300 frames, <= 24 MP in all). "OK" or "Error: ...". */
    external fun encodeJxlAnimated(frames: Array<ByteArray>, width: Int, height: Int, delaysMs: IntArray, hasAlpha: Boolean, outPath: String): String
    /** An animated JPEG XL as GIF. "OK" or "Error: ...". */
    external fun jxlToGif(inPath: String, outPath: String): String
    /** Contact QR preview, no side effects: JSON {name, short_code, safety_code, identity_id, device_fingerprint} or "Error: CODE: ...". */
    external fun peekContactQr(data: ByteArray): String

    // --- Section 5: Group messaging ---
    /** JSON-encoded List<GroupSummary>. */
    external fun listGroups(): String
    external fun createGroup(name: String): String
    /** "OK" or "Error: CODE: detail". */
    external fun inviteToGroup(groupId: String, identityId: String): String
    /** "Retry" on a group bubble: 1 = sent again to the devices that missed
     *  it, 0 = nothing recorded for this id, -1 = nothing could be sent. */
    external fun retryGroupMessageCopies(groupId: String, localId: String): Int
    /** "OK" or "Error: CODE: detail". */
    external fun removeFromGroup(groupId: String, identityId: String): String
    /** Deletes the group for ALL members (a signed `GroupChange::Delete` is sent to everyone). Succeeds ONLY for the founder; otherwise returns "Error: ...". */
    external fun deleteGroup(groupId: String): String
    /** A member who is NOT the founder leaves the group on their own: a leave request goes to the founder (queued for reliable delivery even if the founder is
     *  unreachable right now), and the group record on this device is removed at once. For the founder it returns "Error: ..." (the founder can delete the group
     *  for everyone only with `deleteGroup`). */
    external fun leaveGroup(groupId: String): String
    /** Returns `group_message_local_id` (see the Rust send_group_message note: the fan-out copies sent to N members are merged under ONE local id, which is needed
     *  to match "seen" notices to the right bubble), or "Error: ...".
     *  `replyTo*`: see the same note on `sendMessage`. For groups there is also `replyToSenderIdentityId` (the identity of the replied-to message's sender,
     *  so "reply to <name>" can be shown). `mentionIdsJson`: JSON array of the identity ids of @mentioned members, or null. */
    external fun sendGroupMessage(groupId: String, message: String, replyToMessageId: String?, replyToPreview: String?, replyToSenderIdentityId: String?, mentionIdsJson: String?, expireSecs: Long): String
    /** Group profile photo. It succeeds ONLY for the founder (see Rust set_group_avatar). `avatarJpeg` null removes it. In both cases a GroupUpdate
     *  is sent to ALL members. */
    external fun setGroupProfilePicture(groupId: String, avatarJpeg: ByteArray?): String

    // --- Section 1.8: recovery file ---
    external fun exportRecovery(passphrase: String): ByteArray
    /** After [exportRecovery]: how many newest messages the file holds when it had to be cut; 0 when complete. */
    external fun lastRecoveryTrimmed(): Int
    /** A linked device logging out asks the root device to revoke it; waits up to 3 s. No-op on the root. */
    external fun announceLeaving()

    /** Counterpart of `exportRecovery`, with the SAME pattern as `createIdentity`: on success it returns identity_id and holds the secret bundle, which is then
     *  fetched with [getPendingSecretBundle], encrypted with the Keystore and written to disk (see IdentityManager.persistNewIdentity).
     *  On failure it returns "Error: ..." (wrong passphrase or damaged file). */
    external fun importRecovery(fileBytes: ByteArray, passphrase: String, deviceName: String): String

    // --- Typing indicator ---
    /** Fire-and-forget: it is not archived and does not enter the reliable-delivery queue. The Kotlin side should call it ONLY on false-to-true and
     *  true-to-false transitions, not on every keystroke. */
    external fun sendTypingIndicator(targetDeviceFingerprint: String, isTyping: Boolean): Boolean
    /** See `sendTypingIndicator`, for group chats: sent to ALL reachable other members. */
    external fun sendGroupTypingIndicator(groupId: String, isTyping: Boolean): Boolean

    // --- Profile photo (720p, 85% JPEG) ---
    /** Our own profile photo as currently set, or an empty array if none. */
    external fun getOwnProfilePicture(): ByteArray
    /** `avatarJpeg` null removes the photo. In both cases a `ProfileUpdate` goes to ALL known contacts. The file can be hundreds of KB, so do NOT call it
     *  on the main thread. */
    external fun setOwnProfilePicture(avatarJpeg: ByteArray?): String

    // --- Account name ---
    /** Our current account name (what contacts see us as), or an empty string if none. */
    external fun getDisplayName(): String
    /** Changes the account name and automatically sends the change to ALL known contacts (`ProfileUpdate`, over the ratchet; offline contacts receive it when
     *  they return). The fan-out encrypts separately for each contact, so do NOT call it on the main thread. Returns "OK" on success. */
    external fun setDisplayName(name: String): String

    /** Sends `AccountDeleted` to all contacts and sibling devices (if this device is the group founder, it hands the role over). Returns the number of devices
     *  notified, or `-1` on error. */
    external fun deleteAccount(): Int

    /** Number of account deletion notices not yet confirmed. */
    external fun accountDeletionPending(): Int

    // --- Chat and contact deletion (long-press menu) ---
    /** Soft option: deletes only the local message and attachment history. The pairing is KEPT. */
    external fun clearChatHistory(contactId: String): String
    /** Hard option: deletes the contact completely, including the pairing and ratchet session. Messaging again needs a fresh QR or manual pairing. */
    external fun deleteContact(contactId: String): String
    /** Revokes ONE device of this contact. It does not delete the contact or its history. It only stops everything from and to that device fingerprint
     *  (see Rust revoke_contact_device: is_active is now really checked in receive_message and in the handshake). Example: 'my old phone was stolen,
     *  do not trust that device any more'. */
    external fun revokeContactDevice(contactId: String, deviceFingerprint: String): String
    /** Adds a relay address (Circuit Relay v2) that the user trusts or runs, by hand, for example "/ip4/1.2.3.4/tcp/4001/p2p/12D3Koo...". It is the only way
     *  to guarantee that two people on different networks, with no shared relay history, can pair for the first time. See SECURITY.md, 'Cross-network connectivity'. */
    external fun addKnownRelayAddress(multiaddr: String): String

    // --- Server (store-and-forward) option ---
    //
    // Unlike relays, a server stores envelopes: a relay stores nothing and builds a live circuit only while BOTH sides are connected. A server writes the envelope
    // to disk when the recipient is offline, and delivers it when the recipient returns. The server cannot read the content: envelopes are already end-to-end
    // encrypted and sealed a second time.

    /** Davet kodundan (`typeon-server:<multiaddr>#<jeton>`) sunucu ekler. */
    external fun addServer(inviteCode: String): String

    external fun removeServer(serverId: String): String

    /** `[{server_id, address, name, route_messages, store_history, connected, enrolled, last_error}]` */
    external fun listServers(): String


    external fun setServerRouting(serverId: String, enabled: Boolean): String

    /**
     * Keeping history on the server is separate from message routing, and is on by default. It is turned on automatically when the first server is added
     * (see Rust `server_client::add_server`). The archive is a real backup. Unlike the ratchet, it is NOT forward-secret: if the root archive key ever leaks,
     * all history uploaded up to that point can be read. "I want to see my history on my new device" cannot be reconciled with forward secrecy mathematically,
     * so the trade-off must be the user's explicit choice.
     */
    external fun setServerHistory(serverId: String, enabled: Boolean): String

    /**
     * Will the server in [inviteCode] become THE history server? The core
     * turns `store_history` on only while no server stores history yet, and
     * a server already on the list keeps the record it has (Rust
     * `server_client::add_server`) — so the confirm dialogs show the history
     * warning (and the upload notice) only then.
     *
     * JNI + SQLite: call it off the main thread (see SettingsFragment
     * `refreshServers`). On a read failure the answer stays "yes": when the
     * dialog cannot tell, it warns rather than stays silent.
     */
    fun nextServerStoresHistory(inviteCode: String): Boolean = try {
        val arr = org.json.JSONArray(listServers())
        val rows = (0 until arr.length()).mapNotNull { arr.optJSONObject(it) }
        // The invite ends in `/p2p/<peer_id>`; that string is the `server_id`.
        val mine = inviteCode.substringAfter("/p2p/", "").substringBefore("#")
        rows.none { it.optBoolean("store_history") || (mine.isNotEmpty() && it.optString("server_id") == mine) }
    } catch (e: Exception) {
        true
    }

    /**
     * The root archive key (ARK). The same pattern as `setHistoryKey`, but this key belongs to the IDENTITY, not the device. All devices of one identity must be
     * able to read the archive on the server, so it goes to sibling devices through `DeviceSync` and into the recovery file.
     */
    external fun setArchiveRootKey(keyBytes: ByteArray): Boolean

    /** The ARK in the core (or empty), so an ARK received from a sibling can be written to disk. */
    external fun archiveRootKey(): ByteArray

    /**
     * Downloads the WHOLE history from the server. Used from the recovery file, or by a device freshly set up by linking. Returns `"OK:<number of chats>"`.
     *
     * It differs from the scroll-up flow in the chat: that one assumes the chat is already visible. On a freshly set up device, contacts come back but there are
     * no messages yet, and there is nothing for the user to scroll.
     */
    external fun restoreServerHistory(): String

    /**
     * One chat's older history from the server archive, for a "fetch history
     * from server" button; scrolling up never asks the server. [chatKey]: the
     * peer device fingerprint, or the group id. [beforeTimestamp]: the oldest
     * message on screen (ms), 0 = from the newest. Returns "OK" or
     * "Error: ..."; the rows arrive later with a `history_backfilled` event.
     */
    external fun fetchServerHistory(chatKey: String, isGroup: Boolean, beforeTimestamp: Long): String

    // --- Voice/video calls (Rust `call.rs`) ---
    /** Rings a 1:1 contact device. Returns the call id or "Error: ...". */
    external fun startCall(peerFingerprint: String, video: Boolean): String
    /** Rings every other member of the group. Returns the call id or "Error: ...". */
    external fun startGroupCall(groupId: String, video: Boolean): String
    /** A call running in the group that this device is not in: 0 none, 1 voice, 2 video.
     *  `startGroupCall` then joins it. Changes arrive as `group_call_offer` events. */
    external fun groupCallOffer(groupId: String): Int
    /** Answers the ringing incoming call. */
    external fun acceptCall(): Boolean
    /** Rejects a ringing call, hangs up otherwise. */
    external fun endCall(): Boolean
    /** JSON: `{"state":"idle|outgoing|incoming|active", participants:[{fp,name,joined,slot}], media:{...}}`. */
    external fun callState(): String
    /** Queues one encoded frame (1 = Opus bundle, 2 = H.264) for every participant.
     *  Takes no core lock: safe to call 20-40 times a second from media threads. */
    external fun callSend(kind: Int, data: ByteArray): Boolean
    /** Next received frame `[kind][slot][payload]`, or null after [timeoutMs]. No core lock. */
    external fun callRecv(timeoutMs: Int): ByteArray?
    /** Deepest outgoing link queue, in frames (0..48) — the congestion signal. */
    external fun callBacklog(): Int
    /** Metered (cellular) network: Tor channel padding off; otherwise reduced. */
    external fun setMeteredNetwork(metered: Boolean)
    /** Our decoder for [slot] needs a keyframe; asks that sender in the next report. */
    external fun callRequestKeyframe(slot: Int)
    /** Our HEVC decoder for [slot] failed before its first frame; asks that sender for H.264. */
    external fun callRequestAvc(slot: Int)
    /** True once after a participant asked us to send H.264. */
    external fun callTakeAvcRequest(): Boolean
    /** True once after a participant asked us for a keyframe. */
    external fun callTakeKeyframeRequest(): Boolean

    // --- Shared whiteboard (see whiteboard.rs). Every call names a chat: a
    // group by [groupId], or the 1:1 chat with [peer] when [groupId] is "". ---

    /** A finished stroke on the 1600x1000 board; [points] are little-endian u16
     *  x,y pairs, [shade] 0 light / 1 base / 2 dark, [width] the pen width in
     *  board units (0 = default). Returns the new stroke
     *  ids as hex (16 digits each), or "Error: ...". */
    external fun whiteboardAddStroke(peer: String, groupId: String, page: Int, shade: Int, width: Int, points: ByteArray): String
    /** [ids]: 8 bytes per erased stroke. */
    external fun whiteboardErase(peer: String, groupId: String, ids: ByteArray): String
    /** The board was opened: syncs with the devices that are connected now. */
    external fun whiteboardOpen(peer: String, groupId: String)
    external fun whiteboardMarkRead(peer: String, groupId: String, page: Int)
    /** JSON: `{"pages", "unread" (bit per page), "me", "participants":[{"id","name"}]}`;
     *  the participant order is the colour order. */
    external fun whiteboardInfo(peer: String, groupId: String): String
    /** Per stroke: id(8) shade(1) author index(1, 255 = left) width(1) point count(u16) points. */
    external fun whiteboardPage(peer: String, groupId: String, page: Int): ByteArray
    /** Sends batched strokes / the settling summary if they are due. */
    external fun whiteboardTick()
}
