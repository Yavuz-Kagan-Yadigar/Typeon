//! `P2PCore::new`, database schema and `meta` helpers; SQLCipher key and migration.

use super::*;

impl P2PCore {
    pub(crate) fn new() -> Self {
        // Every JNI-exported `P2PCore` method wraps its body in `catch_panic` (in `jni_exports/mod.rs`). This panic hook is
        // installed here as well because release builds are stripped (`strip = true` in Cargo.toml), so a panic's crash dump would have no symbols.
        // The hook runs BEFORE unwinding starts, so it logs the full panic message and file/line to logcat before `catch_unwind` catches it.
        std::panic::set_hook(Box::new(|info| {
            error!("PANIC caught: {}", info);
            // Tests have no logger: without this a failed assert prints nothing.
            #[cfg(test)]
            eprintln!("PANIC: {info}");
            // a panic on a background thread/task (swarm, Tor, server
            // client) was logged and nothing else; the frontend must hear it.
            CORE_PANICKED.store(true, std::sync::atomic::Ordering::SeqCst);
        }));
        P2PCore {
            db: None,
            identity: None,
            own_devices: HashMap::new(),
            own_device_keys: HashMap::new(),
            known_remote_devices: HashMap::new(),
            last_identity_exchange_reply: HashMap::new(),
            contacts: HashMap::new(),
            identity_to_contact: HashMap::new(),
            ratchets: HashMap::new(),
            recent_handshake_sigs: HashMap::new(),
            early_packets: HashMap::new(),
            early_handshakes: HashMap::new(),
            recent_inbound_digests: HashMap::new(),
            recently_acked: HashMap::new(),
            outbound_acks: HashMap::new(),
            ack_batches_inflight: HashMap::new(),
            last_inbound_dedup_prune_at: 0,
            pending_edits_deletes: HashMap::new(),
            unknown_group_held: HashMap::new(),
            groups: HashMap::new(),
            pending_device_alerts: HashMap::new(),
            swarm: None,
            tor: None,
            tor_enabled: false,
            tor_was_ready: false,
            own_listen_addrs: Vec::new(),
            pending_envelopes: Vec::new(),
            message_status: HashMap::new(),
            node_mode_enabled: false,
            // Same as the midpoint of the settings slider on the Kotlin side (2 GB). See the field documentation.
            history_storage_limit_bytes: 2 * 1024 * 1024 * 1024,
            pending_secret_bundle: None,
            pending_link_target: None,
            pending_link_started_at: 0,
            link_request_open_until: 0,
            link_request_nonce: Vec::new(),
            link_consent_peer: None,
            pending_link_nonce: Vec::new(),
            own_prekeys: Vec::new(),
            own_prekeys_loaded: false,
            peer_prekeys: HashMap::new(),
            id0_inits: std::collections::HashSet::new(),
            own_mailbox_topic_fp: None,
            pairing_mailbox_subs: HashMap::new(),
            pairing_reply_peer: HashMap::new(),
            own_device_add: None,
            sticker_parts: HashMap::new(),
            verified_device_adds: HashMap::new(),
            history_key: None,
            servers: Vec::new(),
            server_rt: HashMap::new(),
            server_inflight: HashMap::new(),
            server_cursors: HashMap::new(),
            server_unknown_mailboxes: HashMap::new(),
            server_unknown_streak: HashMap::new(),
            server_archive_queue: Vec::new(),
            server_blob_uploads: Vec::new(),
            server_sweep_at: 0,
            server_deposited: HashMap::new(),
            server_deposit_locations: HashMap::new(),
            anon_conns: HashMap::new(),
            lazy_deposits: HashMap::new(),
            blob_rtt_sum: 0,
            blob_rtt_count: 0,
            archive_root_key: None,
            skipped_key_encryption_key: None,
            app_files_dir: None,
            device_to_peer_id: HashMap::new(),
            call: None,
            last_call_end: None,
            call_stats_logged_at: 0,
            call_signal_sending: false,
            stream_control: None,
            peer_id_to_addr: HashMap::new(),
            device_last_addr: HashMap::new(),
            device_onion_addr: HashMap::new(),
            last_reconnect_sweep_at: 0,
            last_pending_flush_at: 0,
            auto_resumed_downloads: std::collections::HashSet::new(),
            last_sibling_backfill_at: 0,
            sibling_push_from: None,
            sibling_refresh_at: HashMap::new(),
            sibling_backfill_since: HashMap::new(),
            last_network_change_at: 0,
            network_change_pending: false,
            last_unconfirmed_retry_at: 0,
            last_sibling_roster_sync_at: 0,
            reconnect_backoff: HashMap::new(),
            fast_reconnect_fps: std::collections::HashSet::new(),
            keepalive_state: HashMap::new(),
            deferred_swarm_events: Vec::new(),
            message_rate_limiter: HashMap::new(),
            chunk_rate_limiter: HashMap::new(),
            chunk_bytes_served: HashMap::new(),
            server_mail_rate: (0, 0),
            unknown_peer_rate: (0, 0),
            deferred_incoming: std::collections::VecDeque::new(),
            pending_group_syncs: HashMap::new(),
            pending_group_messages: HashMap::new(),
            group_failed_copies: HashMap::new(),
            history_answered_at: HashMap::new(),
            history_sent_bytes: HashMap::new(),
            history_answered_by: HashMap::new(),
            wb_outbox: HashMap::new(),
            wb_reply_at: HashMap::new(),
            last_group_sync_sweep_at: 0,
            durable_reload_at: 0,
            first_contact_cache: std::cell::RefCell::new(None),
            regen_skip_id: None,
            last_storage_sweep_at: 0,
            known_relay_peers: HashMap::new(),
            fast_reconnect_until: 0,
            relay_listeners: HashMap::new(),
            extra_conns: HashMap::new(),
            bulk_dials: HashMap::new(),
            peer_conns: HashMap::new(),
            conn_rank: HashMap::new(),
            unknown_inbound: HashMap::new(),
            server_rpc_timeouts: HashMap::new(),
            envelopes_inflight: HashMap::new(),
            advertised_onion: None,
            ratchets_loaded: false,
            peer_onion_addr: HashMap::new(),
            bulk_health: HashMap::new(),
            handshake_failure_notified: HashMap::new(),
            last_handshake_redo: HashMap::new(),
            undecryptable_from: HashMap::new(),
            unproven_fails: HashMap::new(),
            outstanding_history_requests: HashMap::new(),
            sibling_fetch_open: HashMap::new(),
            history_fetch_pages: HashMap::new(),
            blocked_identities: std::collections::HashSet::new(),
            deleted_identities: std::collections::HashSet::new(),
            power_save: false,
            metered: false,
            radio_window_at: 0,
            radio_window_open: true,
            tor_dormant: false,
            tor_wake_at: 0,
            resync_since: 0,
            active_downloads: HashMap::new(),
            download_request_ids: HashMap::new(),
            attachment_events: Vec::new(),
            revoked_disconnects: Vec::new(),
            awaiting_confirmation: HashMap::new(),
        }
    }

    /// Android's app-private writable directory cannot be reliably found with `std::env::var("ANDROID_DATA")`, so Kotlin passes it in
    /// (`Context.filesDir.absolutePath`). That is why the database is NOT opened in `new()`: it waits for `init_db` (see JNI `initDatabase`) with the real path.
    pub(crate) fn init_db(&mut self, app_files_dir: &str, storage_key: &[u8; 32]) -> Result<(), rusqlite::Error> {
        // Once per process. Every `MainActivity.onCreate` calls this: it ran
        // the whole migration again, reloaded the maps over live state, and
        // turned messages still being sent into 'error'.
        if self.db.is_some() {
            if self.app_files_dir.as_deref() != Some(app_files_dir) {
                // the open database stays; say so instead of writing to
                // the old path silently.
                error!("init_db: database already open under {:?}, {} ignored", self.app_files_dir, app_files_dir);
            }
            return Ok(());
        }
        let path = format!("{}/{}", app_files_dir, DB_NAME);
        let key_pragma = db_key_pragma(storage_key);
        if is_plain_sqlite(&path) {
            encrypt_plain_db(&path, &key_pragma)?;
        } else {
            // A migration interrupted after the swap left the old plain file behind.
            wipe_file(&format!("{}.plain-old", path));
        }
        let conn = Connection::open(&path)?;
        // First statement on the connection. A wrong key fails on the read.
        conn.execute_batch(&zeroize::Zeroizing::new(format!("PRAGMA key = {};", key_pragma.as_str())))?;
        conn.query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))?;
        // WAL journal and busy_timeout (the server in `typeon-server/src/store/` uses them too). The rollback journal makes every write
        // (ratchet state, transfer progress, skipped keys) a separate fsync-heavy transaction, which costs battery on a phone. busy_timeout
        // turns a lock conflict with a second connection into a wait instead of an immediate SQLITE_BUSY error.
        // secure_delete: deleted rows (acked queue entries, removed contacts) are zeroed instead of lingering in free pages.
        for (k, v) in [("journal_mode", "WAL"), ("synchronous", "NORMAL"), ("secure_delete", "ON")] {
            if let Err(e) = conn.pragma_update(None, k, v) {
                warn!("SQLite PRAGMA {} = {} could not be applied: {}", k, v, e);
            }
        }
        if let Err(e) = conn.busy_timeout(std::time::Duration::from_secs(5)) {
            warn!("SQLite busy_timeout could not be applied: {}", e);
        }
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS identities (id TEXT PRIMARY KEY, primary_device TEXT, avatar_jpeg BLOB);
             CREATE TABLE IF NOT EXISTS own_devices (device_fingerprint TEXT PRIMARY KEY, identity_id TEXT,
                sign_pk_ed25519 BLOB, sign_pk_mldsa BLOB, kem_pk_x25519 BLOB, kem_pk_mlkem BLOB,
                device_name TEXT, is_active INTEGER, last_seen INTEGER);
             CREATE TABLE IF NOT EXISTS contacts (contact_id TEXT PRIMARY KEY, display_name TEXT,
                trusted_identity_id TEXT, known_devices_json TEXT, last_device_change INTEGER, avatar_jpeg BLOB);
             CREATE TABLE IF NOT EXISTS groups (group_id TEXT PRIMARY KEY, founder TEXT, name TEXT,
                version INTEGER, members_json TEXT, created_at INTEGER, avatar_jpeg BLOB);
             -- Not in the spec. A user request (WhatsApp-style reactions): emojis left on a
             -- message. ONE reaction per person, so the key is (message, reactor). A new emoji
             -- overwrites the old one, and a removal deletes the row (see `apply_reaction`).
             -- `reacted_at_ms` stops an old reaction that arrives late from overwriting a newer
             -- one (see packet.rs `Reaction`).
             CREATE TABLE IF NOT EXISTS message_reactions (
                message_id TEXT NOT NULL,
                reactor_identity_id TEXT NOT NULL,
                emoji TEXT NOT NULL,
                reacted_at_ms INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (message_id, reactor_identity_id)
             );
             -- Not in the spec, a bug fix. A received `Seen` (see the `MessageContent::Seen` arm)
             -- used to be written NOWHERE: it only emitted an event, which reached the chat screen
             -- only while that chat was open. A read receipt that arrived while the chat was closed
             -- (or the app was in the background) was lost for good, and the seen-by avatars of a
             -- reopened chat started empty, most visibly in groups. Same pattern as
             -- `message_reactions`: one row per (message, viewer). `load_message_history` and
             -- `load_group_message_history` read it for each row and put it in `ArchivedMessage.seen_by`,
             -- as `reactions_summary` does.
             CREATE TABLE IF NOT EXISTS message_seen (
                message_id TEXT NOT NULL,
                viewer_identity_id TEXT NOT NULL,
                seen_at_ms INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (message_id, viewer_identity_id)
             );

             CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                peer_device_fingerprint TEXT NOT NULL,
                direction TEXT NOT NULL,
                encrypted_blob BLOB NOT NULL,
                nonce BLOB NOT NULL,
                timestamp INTEGER NOT NULL,
                -- Multi-device ordering (not in the spec, a user request): the sender's own send time
                -- (ms). `timestamp` is the LOCAL receive/archive time. A delayed message must be shown
                -- in SEND order, so display and sorting use this column (0/NULL falls back to
                -- `timestamp`). `timestamp` is kept as it is (local, monotonic) for the sync threshold
                -- and paging.
                sent_at_ms INTEGER
             );
             CREATE INDEX IF NOT EXISTS idx_messages_peer ON messages(peer_device_fingerprint, timestamp);
             CREATE TABLE IF NOT EXISTS skipped_message_keys (
                peer_device_fingerprint TEXT NOT NULL,
                message_number INTEGER NOT NULL,
                encrypted_key BLOB NOT NULL,
                nonce BLOB NOT NULL,
                PRIMARY KEY (peer_device_fingerprint, message_number)
             );
             CREATE TABLE IF NOT EXISTS remote_devices (
                device_fingerprint TEXT PRIMARY KEY,
                identity_id TEXT NOT NULL,
                sign_pk_ed25519 BLOB, sign_pk_mldsa BLOB, kem_pk_x25519 BLOB, kem_pk_mlkem BLOB,
                device_name TEXT, is_active INTEGER, last_seen INTEGER
             );
             CREATE TABLE IF NOT EXISTS ratchet_states (
                peer_device_fingerprint TEXT PRIMARY KEY,
                encrypted_state BLOB NOT NULL,
                nonce BLOB NOT NULL,
                updated_at INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS files (
                file_id TEXT PRIMARY KEY,
                peer_device_fingerprint TEXT NOT NULL,
                direction TEXT NOT NULL,
                file_name TEXT NOT NULL,
                mime_type TEXT NOT NULL,
                total_size INTEGER NOT NULL,
                sha256_hex TEXT NOT NULL,
                encrypted_file_key BLOB NOT NULL,
                key_nonce BLOB NOT NULL,
                status TEXT NOT NULL,
                bytes_transferred INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL,
                preview_jpeg BLOB,
                duration_ms INTEGER
             );
             CREATE INDEX IF NOT EXISTS idx_files_peer ON files(peer_device_fingerprint, created_at);
             CREATE TABLE IF NOT EXISTS device_addrs (
                device_fingerprint TEXT PRIMARY KEY,
                multiaddr TEXT NOT NULL,
                updated_at INTEGER NOT NULL
             );
             -- See the `device_onion_addr` field docs. A `.onion` address is kept apart from
             -- `device_addrs`: a LAN or direct address never overwrites it. Otherwise the Tor
             -- reconnect hint, which must not depend on the network, would be lost.
             CREATE TABLE IF NOT EXISTS device_onion_addrs (
                device_fingerprint TEXT PRIMARY KEY,
                multiaddr TEXT NOT NULL,
                updated_at INTEGER NOT NULL
             );
             -- See `persist_durable_retry`: the on-disk copy of the retry queue for Edit, Delete and
             -- GroupUpdate. It must survive a process kill and restart.
             CREATE TABLE IF NOT EXISTS pending_durable_retries (
                message_id TEXT PRIMARY KEY,
                peer_device_fingerprint TEXT NOT NULL,
                content_cbor BLOB NOT NULL,
                created_at INTEGER NOT NULL
             );
             -- See the `pending_group_messages` field docs. This queue used to live only in memory:
             -- if the process was killed while no device of a group member could be resolved, the
             -- messages queued for that member were lost silently, and the user believed they were
             -- sent. Same pattern as `pending_durable_retries`, but one row per queued message. A
             -- member can have several rows: ALL messages queued for it are kept, in order, until
             -- one of its devices is resolved.
             CREATE TABLE IF NOT EXISTS pending_group_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                group_id TEXT NOT NULL,
                member_identity_id TEXT NOT NULL,
                content_cbor BLOB NOT NULL,
                created_at INTEGER NOT NULL
             );
             -- Blocked identities (a user decision). A separate table, so the block survives
             -- deleting the contact record.
             CREATE TABLE IF NOT EXISTS blocked_identities (
                identity_id TEXT PRIMARY KEY,
                blocked_at  INTEGER NOT NULL
             );
             -- Identities that announced their account deletion (see `deleted_identities`).
             CREATE TABLE IF NOT EXISTS deleted_identities (
                identity_id TEXT PRIMARY KEY,
                deleted_at  INTEGER NOT NULL
             );
             -- See `contact_removed_locally`.
             CREATE TABLE IF NOT EXISTS removed_contacts (
                identity_id TEXT PRIMARY KEY
             );
             -- See `journal_sibling_op`: non-additive sibling operations, sent
             -- again to a sibling that was away (`replay_sibling_journal`).
             CREATE TABLE IF NOT EXISTS sibling_journal (
                seq     INTEGER PRIMARY KEY AUTOINCREMENT,
                at      INTEGER NOT NULL,
                dkey    TEXT NOT NULL,
                targets TEXT NOT NULL,
                content BLOB NOT NULL
             );
             -- See `remove_group_locally`.
             CREATE TABLE IF NOT EXISTS removed_groups (
                group_id TEXT PRIMARY KEY,
                -- Group version when it was removed here: an older signed
                -- update must not bring the group back.
                version INTEGER NOT NULL DEFAULT 0
             );
             -- Small key/value store for multi-device (spec 1.5). Only one key is used so far:
             -- `own_device_add`, the signed DeviceAdd (CBOR) of a secondary device linked to an
             -- identity. It is shown to contacts as proof when this device introduces itself (see
             -- `announce_self_to_all_contacts`).
             CREATE TABLE IF NOT EXISTS app_meta (
                k TEXT PRIMARY KEY,
                v BLOB NOT NULL
             );
             -- See `ack_text_packet`.
             CREATE TABLE IF NOT EXISTS acked_packets (
                packet_id TEXT PRIMARY KEY,
                acked_at INTEGER NOT NULL
             );
             -- The age prune runs on every ack: no full scan.
             CREATE INDEX IF NOT EXISTS idx_acked_packets_at ON acked_packets(acked_at);
             -- See `current_own_prekey` / `store_peer_prekey`.
             CREATE TABLE IF NOT EXISTS own_prekeys (id INTEGER PRIMARY KEY, sealed BLOB NOT NULL);
             CREATE TABLE IF NOT EXISTS peer_prekeys (device_fingerprint TEXT PRIMARY KEY, prekey BLOB NOT NULL);
             -- See `remember_sibling_op`. new_text NULL = delete.
             CREATE TABLE IF NOT EXISTS pending_sibling_ops (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_message_id TEXT NOT NULL,
                new_text BLOB,
                edited_at_ms INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL
             );"
        )?;
        // Server (store-and-forward) tables. See `server_client`.
        Self::init_server_tables(&conn);
        conn.execute_batch(whiteboard::SCHEMA)?;
        // SQLite has no `ADD COLUMN IF NOT EXISTS`: only "duplicate column name"
        // means the column is there. Any other failure (disk full, locked)
        // fails init: a missing column made later INSERTs fail silently.
        let migrate = |sql: &str| -> Result<(), rusqlite::Error> {
            match conn.execute(sql, []) {
                Err(e) if !e.to_string().contains("duplicate column name") => {
                    error!("DB migration failed ({}): {}", sql, e);
                    // Only a missing column breaks later writes. An index or
                    // backfill that fails on data (e.g. duplicate rows) would
                    // fail every start, so it stays best-effort.
                    if sql.starts_with("ALTER TABLE") { Err(e) } else { Ok(()) }
                }
                _ => Ok(()),
            }
        };
        migrate("ALTER TABLE removed_groups ADD COLUMN version INTEGER NOT NULL DEFAULT 0")?;
        // When the contact was removed: a pairing after it brings it back on a sibling.
        migrate("ALTER TABLE removed_contacts ADD COLUMN removed_at INTEGER NOT NULL DEFAULT 0")?;
        migrate("ALTER TABLE removed_groups ADD COLUMN founder TEXT NOT NULL DEFAULT ''")?;
        // Added later; fails harmlessly when the column is there.
        migrate("ALTER TABLE wb_tombstones ADD COLUMN seen INTEGER NOT NULL DEFAULT 1")?;
        // Pen width came after the first builds; same ALTER pattern as below.
        migrate("ALTER TABLE wb_strokes ADD COLUMN width INTEGER NOT NULL DEFAULT 0")?;
        migrate("ALTER TABLE wb_strokes ADD COLUMN sig BLOB NOT NULL DEFAULT x''")?;
        // skipped keys expire by age. Rows from before the column count
        // from now.
        migrate("ALTER TABLE skipped_message_keys ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0")?;
        let _ = conn.execute("UPDATE skipped_message_keys SET created_at = ?1 WHERE created_at = 0", params![current_time_ms() as i64]);

        // Migration: the `preview_jpeg` column was added to this table LATER. `CREATE TABLE IF NOT EXISTS` does not alter an existing table, so devices
        // that ran an earlier version need the column added by hand. SQLite has no `ADD COLUMN IF NOT EXISTS`, so the "duplicate column" error
        // is ignored when the column already exists.
        migrate("ALTER TABLE files ADD COLUMN preview_jpeg BLOB")?;
        // Voice message duration.
        migrate("ALTER TABLE files ADD COLUMN duration_ms INTEGER")?;
        // The chunk size is now per file (see `attachments::FILE_CHUNK_SIZE_V2`).
        // NULL = legacy 256 KiB, so existing rows work as before.
        migrate("ALTER TABLE files ADD COLUMN chunk_size INTEGER")?;
        migrate("ALTER TABLE identities ADD COLUMN avatar_jpeg BLOB")?;
        migrate("ALTER TABLE contacts ADD COLUMN avatar_jpeg BLOB")?;
        // Whether a contact was added through a group (with the founder's vouch). See Contact.added_via_group.
        migrate("ALTER TABLE contacts ADD COLUMN added_via_group INTEGER")?;
        if let Err(e) = conn.execute_batch(CONTACTS_ONE_ROW_PER_IDENTITY_SQL) {
            error!("contacts unique index could not be created: {}", e);
        }
        migrate("ALTER TABLE groups ADD COLUMN avatar_jpeg BLOB")?;
        // See `packet::FounderTransfer`. The founder transfer chain prevents a missed transfer from permanently removing a member from the group.
        migrate("ALTER TABLE groups ADD COLUMN founder_chain_json TEXT")?;
        // Group history and send status. Rows with `group_id` set are group messages. For them peer_device_fingerprint is an empty string:
        // the column is NOT NULL, and '' marks "not a 1:1 chat". `sender_identity_id` stores the author, since a group has many senders.
        // `message_id` / `status` (pending, sent or error) are kept on disk, so a restart does not show every row as "sent".
        migrate("ALTER TABLE messages ADD COLUMN group_id TEXT")?;
        migrate("ALTER TABLE messages ADD COLUMN sender_identity_id TEXT")?;
        // See the `sent_at_ms` note on the messages table: send-order display.
        migrate("ALTER TABLE messages ADD COLUMN sent_at_ms INTEGER")?;
        migrate("ALTER TABLE messages ADD COLUMN message_id TEXT")?;
        migrate("ALTER TABLE messages ADD COLUMN status TEXT")?;
        migrate("CREATE INDEX IF NOT EXISTS idx_messages_group ON messages(group_id, timestamp)")?;
        migrate("CREATE INDEX IF NOT EXISTS idx_messages_message_id ON messages(message_id)")?;
        // The chat list and paging sort by the effective send time (`sent_at_ms`). Without these, each preview
        // sorted all rows of its chat.
        migrate("CREATE INDEX IF NOT EXISTS idx_messages_peer_sent ON messages(peer_device_fingerprint, COALESCE(NULLIF(sent_at_ms, 0), timestamp))")?;
        migrate("CREATE INDEX IF NOT EXISTS idx_messages_group_sent ON messages(group_id, COALESCE(NULLIF(sent_at_ms, 0), timestamp))")?;
        // Reply context (swipe-to-reply). See the packet.rs `MessageContent::Text.reply_to_*` docs. If these were not persisted in the archive too,
        // the reply preview would be lost whenever the chat history was reloaded (app or screen reopened).
        migrate("ALTER TABLE messages ADD COLUMN reply_to_message_id TEXT")?;
        migrate("ALTER TABLE messages ADD COLUMN reply_to_preview TEXT")?;
        migrate("ALTER TABLE messages ADD COLUMN reply_to_sender_identity_id TEXT")?;
        // Edit/Delete previously only updated the live in-memory adapter —
        // the archived copy kept the original text and reappeared on
        // reopen/reload. `is_deleted` marks a soft delete; an edit
        // re-encrypts and overwrites encrypted_blob/nonce in place (see
        // apply_edit_to_archive/apply_delete_to_archive).
        migrate("ALTER TABLE messages ADD COLUMN is_deleted INTEGER NOT NULL DEFAULT 0")?;
        // See `ArchivedMessage.is_edited`. The edited flag is persisted too.
        migrate("ALTER TABLE messages ADD COLUMN is_edited INTEGER NOT NULL DEFAULT 0")?;
        // Owner decision: the row came from a contact's 1:1
        // history answer, at a time the contact stated. The UI marks it.
        migrate("ALTER TABLE messages ADD COLUMN via_sync INTEGER NOT NULL DEFAULT 0")?;
        // Sender timestamp (`MessageContent::Edit.edited_at_ms`) of the last applied edit. `apply_edit_to_archive` uses it so an edit with an OLDER
        // timestamp cannot overwrite a NEWER one (0 = never edited, or an old packet with no ordering info).
        migrate("ALTER TABLE messages ADD COLUMN edit_ts INTEGER NOT NULL DEFAULT 0")?;
        // Group rows taken from another member's history answer: that member's identity id until the author's own copy
        // arrives (`ArchivedMessage.relayed_by`).
        migrate("ALTER TABLE messages ADD COLUMN relayed_by TEXT")?;
        // Group rows: my identity id was in the sender's @mention list.
        migrate("ALTER TABLE messages ADD COLUMN mentions_me INTEGER NOT NULL DEFAULT 0")?;
        // Disappearing messages: the timer (seconds) and when this row goes (local clock, ms). See `Core::expire_due`.
        migrate("ALTER TABLE messages ADD COLUMN expire_secs INTEGER")?;
        migrate("ALTER TABLE messages ADD COLUMN expire_at_ms INTEGER")?;
        migrate("CREATE INDEX IF NOT EXISTS idx_messages_expire ON messages(expire_at_ms) WHERE expire_at_ms IS NOT NULL")?;
        // one row per message id (per group; 1:1 rows share the scope
        // ''). Once, before the index: a deleted copy wins (the user's delete),
        // then an edited one, one from its author, then the earliest.
        // Reactions/seen point at the message_id text, which the kept row has.
        let has_unique: bool = conn.query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = 'idx_messages_msgid_unique'", [], |_| Ok(()),
        ).is_ok();
        if !has_unique {
            if let Err(e) = conn.execute(
                "DELETE FROM messages WHERE id IN (
                    SELECT id FROM (SELECT id, ROW_NUMBER() OVER (
                        PARTITION BY COALESCE(group_id, ''), message_id
                        ORDER BY is_deleted DESC, is_edited DESC, (relayed_by IS NULL) DESC, id ASC) AS rn
                    FROM messages WHERE message_id IS NOT NULL AND message_id != '') WHERE rn > 1)",
                [],
            ) {
                error!("DB migration failed (message_id dedupe): {}", e);
            }
            migrate("CREATE UNIQUE INDEX IF NOT EXISTS idx_messages_msgid_unique ON messages(COALESCE(group_id, ''), message_id) WHERE message_id IS NOT NULL AND message_id != ''")?;
        }
        // Group attachments use the same pattern as `messages`: `peer_device_fingerprint = ''` plus `group_id` (see `archive_group_message`), and the sender
        // is told apart by `sender_identity_id` (see `prepare_and_send_group_file` / `receive_file_offer`).
        // Attachments carry their caption and reply context too. Carrying them only in the live event is not enough: chats read from the archive on reopen,
        // so the caption and reply context would be lost.
        migrate("ALTER TABLE files ADD COLUMN caption TEXT")?;
        migrate("ALTER TABLE files ADD COLUMN reply_to_message_id TEXT")?;
        migrate("ALTER TABLE files ADD COLUMN reply_to_preview TEXT")?;
        migrate("ALTER TABLE files ADD COLUMN reply_to_sender_identity_id TEXT")?;
        migrate("ALTER TABLE files ADD COLUMN group_id TEXT")?;
        migrate("ALTER TABLE files ADD COLUMN sender_identity_id TEXT")?;
        migrate("CREATE INDEX IF NOT EXISTS idx_files_group ON files(group_id, created_at)")?;
        migrate("ALTER TABLE files ADD COLUMN sticker INTEGER NOT NULL DEFAULT 0")?;
        // My sticker store: `stickers/<id>.enc`, keyed like attachments.
        migrate("CREATE TABLE IF NOT EXISTS stickers (id TEXT PRIMARY KEY, created_at INTEGER NOT NULL, animated INTEGER NOT NULL, encrypted_key BLOB NOT NULL, key_nonce BLOB NOT NULL)")?;
        migrate("ALTER TABLE stickers ADD COLUMN favorite INTEGER NOT NULL DEFAULT 0")?;
        // Sticker folders: this device only, like `favorite`. A sticker can sit in several folders.
        migrate("CREATE TABLE IF NOT EXISTS sticker_folders (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, created_at INTEGER NOT NULL)")?;
        migrate("CREATE TABLE IF NOT EXISTS sticker_folder_items (folder_id INTEGER NOT NULL, sticker_id TEXT NOT NULL, PRIMARY KEY (folder_id, sticker_id))")?;
        // Stable identity across devices, see `FileOffer.sticker_origin`.
        migrate("ALTER TABLE stickers ADD COLUMN origin_id TEXT")?;
        migrate("UPDATE stickers SET origin_id = 'jxl:' || id WHERE origin_id IS NULL")?;
        migrate("CREATE UNIQUE INDEX IF NOT EXISTS idx_stickers_origin ON stickers(origin_id)")?;
        migrate("ALTER TABLE files ADD COLUMN sticker_origin TEXT")?;
        // Disappearing attachments, as `messages`. `expire_secs = 0`: my own sent file, hidden, its `.enc` kept until `expire_at_ms` so a
        // receiver still offline can download it (see `Core::expire_due`).
        migrate("ALTER TABLE files ADD COLUMN expire_secs INTEGER")?;
        migrate("ALTER TABLE files ADD COLUMN expire_at_ms INTEGER")?;
        migrate("CREATE INDEX IF NOT EXISTS idx_files_expire ON files(expire_at_ms) WHERE expire_at_ms IS NOT NULL")?;
        migrate("CREATE INDEX IF NOT EXISTS idx_files_sticker_origin ON files(sticker_origin)")?;
        // `FileOffer.chunk_hashes`: each received chunk is checked against it.
        migrate("ALTER TABLE files ADD COLUMN chunk_hashes BLOB")?;
        // The sender's send time (order key of the bubble), the send status of my own offer, automatic restarts of a failed download.
        migrate("ALTER TABLE files ADD COLUMN sent_at_ms INTEGER")?;
        migrate("ALTER TABLE files ADD COLUMN send_status TEXT")?;
        migrate("ALTER TABLE files ADD COLUMN auto_resumes INTEGER NOT NULL DEFAULT 0")?;
        // The start-up pending sweep below, the storage-limit sum and the shared-copy lookup read these.
        migrate("CREATE INDEX IF NOT EXISTS idx_messages_pending ON messages(status) WHERE status = 'pending'")?;
        migrate("CREATE INDEX IF NOT EXISTS idx_files_status ON files(status)")?;
        migrate("CREATE INDEX IF NOT EXISTS idx_files_sha ON files(sha256_hex)")?;
        // the group row id of a queued copy (its own ids are per member).
        migrate("ALTER TABLE pending_group_messages ADD COLUMN local_message_id TEXT")?;
        migrate("ALTER TABLE pending_durable_retries ADD COLUMN local_message_id TEXT")?;
        // The sealed (envelope, chain stamp) last published for the row: a restart offers the same bytes again.
        migrate("ALTER TABLE pending_durable_retries ADD COLUMN sent_cbor BLOB")?;
        // A 'pending' row left by the previous run with no retry behind it
        // would show the clock icon forever: mark it failed. Rows whose send
        // is restored by `load_pending_durable_retries_from_db` stay pending,
        // and so do group rows with a copy still queued (`local_message_id`
        // in `pending_group_messages` or the durable retries): marking those
        // failed made the user resend a message that was then delivered twice.
        // expired retries first, or their rows are skipped here and
        // nothing ever fails them.
        let _ = conn.execute(
            "DELETE FROM pending_durable_retries WHERE created_at < ?1",
            params![current_time_ms().saturating_sub(TEXT_RETRY_GIVE_UP_MS) as i64],
        );
        let _ = conn.execute(
            "UPDATE messages SET status = 'error' WHERE status = 'pending'
               AND (message_id IS NULL OR (
                    message_id NOT IN (SELECT message_id FROM pending_durable_retries)
                AND message_id NOT IN (SELECT local_message_id FROM pending_durable_retries WHERE local_message_id IS NOT NULL)
                AND message_id NOT IN (SELECT local_message_id FROM pending_group_messages WHERE local_message_id IS NOT NULL)))",
            [],
        );
        // No download is running at start, so a 'downloading' row is dead. Its owner reconnecting resumes it, or the user can retry.
        // The partial `.enc` file stays on disk: `download_file` resumes from the verified chunks, and the quota counts 'failed' bytes.
        let _ = conn.execute("UPDATE files SET status = 'failed' WHERE status = 'downloading'", []);
        self.db = Some(conn);
        self.app_files_dir = Some(app_files_dir.to_string());
        // Decrypted copies do not outlive the process: an opened attachment
        // is decrypted again on the next view.
        let _ = std::fs::remove_dir_all(format!("{}/attachments/plain_cache", app_files_dir));
        let _ = std::fs::create_dir_all(format!("{}/attachments/plain_cache", app_files_dir));
        #[cfg(unix)]
        {
            // Plaintext: not for the other users of a desktop.
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(format!("{}/attachments/plain_cache", app_files_dir), std::fs::Permissions::from_mode(0o700));
        }
        // Encrypted conversions (`keep_conversion`): kept across starts and locks.
        let _ = std::fs::create_dir_all(format!("{}/attachments/sticker_cache", app_files_dir));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(format!("{}/attachments/sticker_cache", app_files_dir), std::fs::Permissions::from_mode(0o700));
        }
        self.sweep_orphan_enc_files();
        self.load_identity_from_db();
        // Contacts, groups and known remote device keys are written on every change (see persist_contact, persist_group and
        // persist_remote_device) and reloaded here. Ratchet sessions are restored separately, once the encryption key is loaded
        // (see load_ratchet_states_from_db).
        self.load_contacts_from_db();
        self.load_groups_from_db();
        self.load_remote_devices_from_db();
        self.load_device_addrs_from_db();
        self.load_device_onion_addrs_from_db();
        self.load_own_device_add_from_db();
        self.load_blocked_from_db();
        Ok(())
    }

    /// Multi-device: if this device was linked to an identity as a secondary device, loads the stored signed `DeviceAdd`
    /// (the proof we present when introducing ourselves to contacts) into memory.
    pub(crate) fn load_own_device_add_from_db(&mut self) {
        let conn = match &self.db { Some(c) => c, None => return };
        let blob: Option<Vec<u8>> = conn
            .query_row("SELECT v FROM app_meta WHERE k = 'own_device_add'", [], |r| r.get(0))
            .ok();
        if let Some(bytes) = blob {
            match ciborium::from_reader::<DeviceAdd, _>(bytes.as_slice()) {
                Ok(da) => self.own_device_add = Some(da),
                // Without it this device cannot prove its identity to contacts.
                Err(e) => error!("own_device_add could not be resolved: {}", e),
            }
        }
        // See `outstanding_history_requests`: pending history requests.
        if let Ok(mut stmt) = conn.prepare("SELECT k, v FROM app_meta WHERE k LIKE 'hsr:%'") {
            if let Ok(rows) = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))) {
                for (k, v) in rows.flatten() {
                    if let Ok(entry) = serde_json::from_str::<(Option<String>, Option<String>, u64, Option<(i64, i64)>)>(&v) {
                        self.outstanding_history_requests.insert(k["hsr:".len()..].to_string(), entry);
                    }
                }
            }
        }
        // See `link_request_open_until`: the window stays valid even if the process dies.
        self.link_request_open_until = conn
            .query_row("SELECT v FROM app_meta WHERE k = 'link_request_open_until'", [], |r| r.get::<_, i64>(0))
            .map(|v| v.max(0) as u64)
            .unwrap_or(0);
        // The primary's half of a link (`set_pending_link`), the unanswered
        // device alerts and the handshake replay guard survive a restart too.
        let meta = |k: &str| conn.query_row("SELECT v FROM app_meta WHERE k = ?1", params![k], |r| r.get::<_, String>(0)).ok();
        if let Some((fp, at)) = meta("pending_link").and_then(|v| serde_json::from_str::<(String, u64)>(&v).ok()) {
            self.pending_link_target = Some(fp);
            self.pending_link_started_at = at;
        }
        if let Ok(mut stmt) = conn.prepare("SELECT device_fingerprint, prekey FROM peer_prekeys") {
            if let Ok(rows) = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))) {
                for (fp, cbor) in rows.flatten() {
                    if let Ok(pk) = ciborium::from_reader::<SignedPrekey, _>(cbor.as_slice()) {
                        self.peer_prekeys.insert(fp, pk);
                    }
                }
            }
        }
        // Both halves of the link nonce survive a restart with their windows.
        self.pending_link_nonce = meta("pending_link_nonce").and_then(|v| hex::decode(v).ok()).unwrap_or_default();
        self.link_request_nonce = meta("link_request_nonce").and_then(|v| hex::decode(v).ok()).unwrap_or_default();
        if let Some(alerts) = meta("device_alerts").and_then(|v| serde_json::from_str(&v).ok()) {
            self.pending_device_alerts = alerts;
        }
        let now = current_time_ms();
        if let Ok(mut stmt) = conn.prepare("SELECT k, v FROM app_meta WHERE k LIKE 'hs:%'") {
            let mut expired: Vec<String> = Vec::new();
            if let Ok(rows) = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))) {
                for (k, v) in rows.flatten() {
                    let sigs: Vec<(u64, Vec<u8>)> = serde_json::from_str::<Vec<(u64, String)>>(&v).unwrap_or_default().into_iter()
                        .filter(|(ts, _)| now.abs_diff(*ts) <= HANDSHAKE_MAX_AGE_MS)
                        .filter_map(|(ts, sig)| hex::decode(sig).ok().map(|s| (ts, s)))
                        .collect();
                    if sigs.is_empty() {
                        expired.push(k);
                    } else {
                        self.recent_handshake_sigs.insert(k["hs:".len()..].to_string(), sigs);
                    }
                }
            }
            // A row with only expired entries was kept on disk for good.
            for k in expired {
                let _ = conn.execute("DELETE FROM app_meta WHERE k = ?1", params![k]);
            }
        }
    }

    pub(crate) fn meta_put(&self, k: &str, v: &str) {
        bump_first_contact_gen(k);
        match &self.db {
            Some(conn) => {
                if let Err(e) = conn.execute("INSERT OR REPLACE INTO app_meta (k, v) VALUES (?1, ?2)", params![k, v]) {
                    error!("app_meta could not be written ({}): {}", k.split(':').next().unwrap_or(""), e);
                }
            }
            None => warn!("app_meta could not be written ({}): no DB", k.split(':').next().unwrap_or("")),
        }
    }

    /// Rows of the 1:1 chat with `identity_id` older than this were deleted
    /// by the user (clear chat or delete contact): no backfill may bring them back.
    pub(crate) fn history_floor(&self, identity_id: &str) -> u64 {
        self.meta_str(&format!("hfloor:{}", identity_id))
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0)
    }

    /// Raises the history floor of a chat (identity id or group id) to `ms`;
    /// never lowers it. Every clear, prune and contact delete comes here, so
    /// it also drops the chat's "Fetch older history" state
    /// (`forget_history_fetch`).
    pub(crate) fn raise_history_floor(&mut self, chat_id: &str, ms: u64) {
        if ms > self.history_floor(chat_id) {
            self.meta_put(&format!("hfloor:{}", chat_id), &ms.to_string());
        }
        self.forget_history_fetch(chat_id);
    }

    /// A user's "Fetch older history" wrote rows back: the floor goes down to
    /// `ms`, the oldest row written, so those rows are no longer "cleared".
    /// Only that path calls this; it never raises the floor.
    pub(crate) fn lower_history_floor(&self, chat_id: &str, ms: u64) {
        if ms < self.history_floor(chat_id) {
            self.meta_put(&format!("hfloor:{}", chat_id), &ms.to_string());
        }
    }

    /// A press's window was not fully asked for (a source went away, a
    /// follow-up page was not sent): the cursor `hfetch:` goes back up to
    /// `to`, so the next press asks for the rest again (rows dedup by id).
    /// Without a cursor (none yet, or a clear) nothing changes.
    pub(crate) fn reopen_fetch_cursor(&self, conv_key: &str, to: u64) {
        let k = format!("hfetch:{}", conv_key);
        if self.meta_str(&k).and_then(|v| v.parse::<u64>().ok()).is_some_and(|c| c < to) {
            self.meta_put(&k, &to.to_string());
        }
    }

    /// Forgets the "Fetch older history" state of a chat (identity id or
    /// group id): its cursor, its open press requests to peers and own
    /// devices, its follow-up budget and a running server page chain. A
    /// late answer is then unsolicited and cannot bring cleared rows back.
    pub(crate) fn forget_history_fetch(&mut self, chat_id: &str) {
        self.meta_del(&format!("hfetch:{}", chat_id));
        let ids: Vec<String> = self.outstanding_history_requests.iter()
            .filter(|(_, (target, group, _, window))| window.is_some() && group.as_deref().or(target.as_deref()) == Some(chat_id))
            .map(|(id, _)| id.clone())
            .collect();
        for id in ids {
            self.awaiting_confirmation.remove(&id);
            self.remove_durable_retry(&id);
            self.forget_history_request(&id);
        }
        self.sibling_fetch_open.retain(|_, (chat, _)| chat != chat_id);
        self.history_fetch_pages.remove(chat_id);
        self.drop_archive_page_chains(chat_id);
    }

    /// Where the next "Fetch older history" press of a chat ends its window:
    /// the stored cursor (`hfetch:`, moved one window back by every press),
    /// else the oldest local row's send time, else now. For that first value
    /// rows sent before `HISTORY_FETCH_EPOCH_MS`, or more than one window
    /// before the oldest arrival time, are ignored: one row with a bad clock
    /// must not send every press to 1970. `conv_key` is the identity id or
    /// group id, `peer_device_fingerprint` the canonical 1:1 chat key.
    pub(crate) fn history_fetch_cursor(&self, conv_key: &str, peer_device_fingerprint: &str, group_id: Option<&str>) -> u64 {
        if let Some(c) = self.meta_str(&format!("hfetch:{}", conv_key)).and_then(|v| v.parse::<u64>().ok()) {
            return c;
        }
        let (cond, key) = match group_id {
            Some(g) => ("group_id = ?1", g),
            None => ("peer_device_fingerprint = ?1 AND group_id IS NULL", peer_device_fingerprint),
        };
        let at = "COALESCE(NULLIF(sent_at_ms,0), timestamp)";
        let oldest = self.db.as_ref().and_then(|conn| conn.query_row(
            &format!("SELECT MIN({at}) FROM messages WHERE {cond} AND {at} >= ?2
                        AND {at} >= COALESCE((SELECT MIN(timestamp) FROM messages WHERE {cond} AND timestamp >= ?2), 0) - ?3"),
            params![key, HISTORY_FETCH_EPOCH_MS, HISTORY_FETCH_WINDOW_MS as i64],
            |r| r.get::<_, Option<i64>>(0),
        ).ok().flatten());
        oldest.map_or_else(current_time_ms, |v| v.max(0) as u64)
    }

    pub(crate) fn meta_del(&self, k: &str) {
        bump_first_contact_gen(k);
        if let Some(conn) = &self.db {
            let _ = conn.execute("DELETE FROM app_meta WHERE k = ?1", params![k]);
        }
    }

    /// `pending_link_target` + `pending_link_started_at`, also on disk. In
    /// memory only, a process kill between the QR scan and the secondary's
    /// IdentityExchange made that packet a stranger's: the secondary became a
    /// TOFU contact and never got its grant.
    pub(crate) fn set_pending_link(&mut self, target: Option<String>) {
        self.pending_link_started_at = if target.is_some() { current_time_ms() } else { 0 };
        match &target {
            Some(fp) => self.meta_put("pending_link", &serde_json::json!([fp, self.pending_link_started_at]).to_string()),
            None => self.meta_del("pending_link"),
        }
        self.pending_link_target = target;
    }

    /// `pending_device_alerts` on disk: the IdentityExchange that raised an
    /// alert is dropped, so an alert lost with the process left the device
    /// blocked with nothing to answer.
    pub(crate) fn persist_device_alerts(&self) {
        if let Ok(v) = serde_json::to_string(&self.pending_device_alerts) {
            self.meta_put("device_alerts", &v);
        }
    }

    /// `recent_handshake_sigs` of one peer on disk. In memory only, a
    /// HandshakeInit captured from the mailbox topic passed again after a
    /// process restart inside `HANDSHAKE_MAX_SKEW_MS` and replaced the live
    /// session.
    pub(crate) fn persist_handshake_sigs(&self, fp: &str) {
        match self.recent_handshake_sigs.get(fp) {
            Some(sigs) if !sigs.is_empty() => {
                let v: Vec<(u64, String)> = sigs.iter().map(|(ts, s)| (*ts, hex::encode(s))).collect();
                self.meta_put(&format!("hs:{}", fp), &serde_json::to_string(&v).unwrap_or_default());
            }
            _ => self.meta_del(&format!("hs:{}", fp)),
        }
    }

    pub(crate) fn set_link_request_open_until(&mut self, until: u64) {
        self.link_request_open_until = until;
        if until == 0 {
            // Closed (adopted, or the QR screen was left): the code is spent.
            self.link_request_nonce.clear();
            self.link_consent_peer = None;
            self.meta_del("link_request_nonce");
        }
        if let Some(conn) = &self.db {
            let _ = conn.execute(
                "INSERT OR REPLACE INTO app_meta (k, v) VALUES ('link_request_open_until', ?1)",
                params![until as i64],
            );
        }
    }

    pub(crate) fn persist_own_device_add(&self, device_add: &DeviceAdd) {
        let conn = match &self.db { Some(c) => c, None => return };
        if let Ok(bytes) = ciborium_bytes(device_add) {
            let _ = conn.execute(
                "INSERT OR REPLACE INTO app_meta (k, v) VALUES ('own_device_add', ?1)",
                params![bytes],
            );
        }
    }

    /// Loads known device addresses (`device_last_addr`) from disk into memory, so that after a process restart `reconnect_sweep` can still retry
    /// disconnected contacts, including those on other networks where mDNS cannot find them.
    /// Loopback entries are filtered out here, not deleted. `remember_device_addr` rejects loopback addresses, but a loopback row written BEFORE that
    /// fix stays in the `device_addrs` table. It is never loaded, so an existing install heals on the next start without a manual DB cleanup:
    /// `try_reconnect_device` finds no address for that device and returns `false` until a real address is learned (mDNS, relay discovery, or QR).
    pub(crate) fn load_device_addrs_from_db(&mut self) {
        let conn = match &self.db { Some(c) => c, None => return };
        let mut stmt = match conn.prepare("SELECT device_fingerprint, multiaddr FROM device_addrs") {
            Ok(s) => s,
            Err(e) => { log::error!("device_addrs could not be loaded: {e}"); return }
        };
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)));
        if let Ok(rows) = rows {
            for (fp, addr) in rows.flatten() {
                if addr.parse::<Multiaddr>().map(|a| is_loopback_multiaddr(&a)).unwrap_or(false) {
                    continue;
                }
                self.device_last_addr.insert(fp, addr);
            }
        }
    }

    /// See the `device_onion_addr` field docs. Same pattern as `load_device_addrs_from_db`, separate table.
    pub(crate) fn load_device_onion_addrs_from_db(&mut self) {
        let conn = match &self.db { Some(c) => c, None => return };
        let mut stmt = match conn.prepare("SELECT device_fingerprint, multiaddr FROM device_onion_addrs") {
            Ok(s) => s,
            Err(e) => { log::error!("device_onion_addrs could not be loaded: {e}"); return }
        };
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)));
        if let Ok(rows) = rows {
            for (fp, addr) in rows.flatten() {
                self.device_onion_addr.insert(fp, addr);
            }
        }
    }

    /// Updates a device's most recently working address in memory and on disk (see `device_last_addr`). The address must end with `/p2p/<peer_id>`,
    /// because `reconnect_sweep` takes the PeerId from there. Addresses without it are ignored (they cannot be used to reconnect).
    /// Loopback addresses (127.0.0.1 / ::1) are ignored for the same reason (see `is_loopback_multiaddr`). Two devices on the same machine (for example two
    /// emulators with ADB port forwarding during development) can produce such an address, but it never works between real devices. Before this check,
    /// such an address learned via `ConnectionEstablished` (through `peer_id_to_addr`, see `record_peer_id_if_known`) was saved as a persistent reconnect hint.
    /// The device then dialed that dead loopback address on every periodic sweep (`try_reconnect_device`). The only way to learn a real address was a
    /// successful connection, which never happened.
    pub(crate) fn remember_device_addr(&mut self, device_fingerprint: &str, multiaddr: &str) {
        let parsed = match multiaddr.parse::<Multiaddr>() {
            Ok(p) => p,
            Err(_) => return,
        };
        if extract_peer_id(&parsed).is_none() || is_loopback_multiaddr(&parsed) {
            return;
        }
        // Tor fallback: if this address is a `.onion`, it is ALSO written to the separate `device_onion_addr` (see that field), in addition to the general
        // `device_last_addr` update above (which tracks the last working address of any kind for the live chat status). LAN or direct addresses never overwrite
        // `device_onion_addr`. So if a device paired over Tor loses the LAN link and moves to mobile data, the Tor address is still known.
        // Without this, a device on the same LAN and paired over Tor could not be reached after a network switch.
        if is_onion_multiaddr(&parsed) {
            self.remember_onion_addr(device_fingerprint, multiaddr);
        }
        // Skip the disk write if nothing changed (avoids needless I/O).
        if self.device_last_addr.get(device_fingerprint).map(|a| a.as_str()) == Some(multiaddr) {
            return;
        }
        self.device_last_addr.insert(device_fingerprint.to_string(), multiaddr.to_string());
        if let Some(conn) = &self.db {
            let _ = conn.execute(
                "INSERT OR REPLACE INTO device_addrs (device_fingerprint, multiaddr, updated_at) VALUES (?1, ?2, ?3)",
                params![device_fingerprint, multiaddr, current_time_ms() as i64],
            );
        }
    }

    /// See the `device_onion_addr` field docs. Same pattern as `remember_device_addr` (no write if unchanged), but it writes to its OWN table/map and a
    /// LAN or direct address never overwrites it. Only a newer `.onion` address replaces it, for example if the Tor identity changes (rare in practice,
    /// since `ONION_NICKNAME` is fixed and the same device always gets the same .onion).
    pub(crate) fn remember_onion_addr(&mut self, device_fingerprint: &str, multiaddr: &str) {
        if self.device_onion_addr.get(device_fingerprint).map(|a| a.as_str()) == Some(multiaddr) {
            return;
        }
        self.device_onion_addr.insert(device_fingerprint.to_string(), multiaddr.to_string());
        if let Some(conn) = &self.db {
            let _ = conn.execute(
                "INSERT OR REPLACE INTO device_onion_addrs (device_fingerprint, multiaddr, updated_at) VALUES (?1, ?2, ?3)",
                params![device_fingerprint, multiaddr, current_time_ms() as i64],
            );
        }
    }
}

/// SQLCipher raw key (no passphrase KDF at open), as the quoted `x'..'`
/// literal. Derived from the local storage key (the `seal_local_blob` key)
/// under its own label, so the two ciphers never share key bytes.
pub(crate) fn db_key_pragma(storage_key: &[u8; 32]) -> zeroize::Zeroizing<String> {
    let mut key = zeroize::Zeroizing::new([0u8; 32]);
    Hkdf::<sha2::Sha256>::new(None, storage_key)
        .expand(b"typeon-db-sqlcipher-v1", &mut key[..])
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    let hex_key = zeroize::Zeroizing::new(hex::encode(&key[..]));
    zeroize::Zeroizing::new(format!("\"x'{}'\"", hex_key.as_str()))
}

/// Overwrites a file with zeros, syncs it and removes it. Best effort: flash wear levelling may keep old copies.
pub(crate) fn wipe_file(path: &str) {
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(path) {
        let zeros = [0u8; 64 * 1024];
        let mut left = f.metadata().map_or(0, |m| m.len());
        while left > 0 {
            let n = left.min(zeros.len() as u64) as usize;
            if f.write_all(&zeros[..n]).is_err() {
                break;
            }
            left -= n as u64;
        }
        let _ = f.sync_all();
    }
    let _ = std::fs::remove_file(path);
}

pub(crate) fn is_plain_sqlite(path: &str) -> bool {
    use std::io::Read;
    let mut magic = [0u8; 16];
    std::fs::File::open(path).and_then(|mut f| f.read_exact(&mut magic)).is_ok() && &magic == b"SQLite format 3\0"
}

/// One-time: replaces the plain database at `path` with an encrypted copy.
/// The plain file stays in place until the copy is complete, verified and
/// synced, and the swap is one `rename`: an interrupted run leaves the plain
/// database (plus a temp file) and the next start runs this again.
pub(crate) fn encrypt_plain_db(path: &str, key_pragma: &str) -> Result<(), rusqlite::Error> {
    fn io(e: std::io::Error) -> rusqlite::Error {
        rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_IOERR), Some(e.to_string()))
    }
    let tmp = format!("{}.enc-tmp", path);
    for suffix in ["", "-journal", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{}", tmp, suffix));
    }
    let objects = |c: &Connection| c.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get::<_, i64>(0));
    let plain = Connection::open(path)?;
    // Fold the WAL into the main file and leave WAL mode: a plain `-wal` next
    // to the encrypted file would be replayed into it.
    let mode: String = plain.query_row("PRAGMA journal_mode = DELETE", [], |r| r.get(0))?;
    if !mode.eq_ignore_ascii_case("delete") {
        return Err(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY),
            Some("plain database is still in WAL mode".to_string()),
        ));
    }
    let expected = objects(&plain)?;
    let user_version: i64 = plain.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    plain.execute_batch(&zeroize::Zeroizing::new(format!("ATTACH DATABASE '{}' AS enc KEY {};", tmp.replace('\'', "''"), key_pragma)))?;
    plain.query_row("SELECT sqlcipher_export('enc')", [], |_| Ok(()))?;
    plain.execute_batch(&format!("PRAGMA enc.user_version = {}; DETACH DATABASE enc;", user_version))?;
    drop(plain);

    let encrypted = Connection::open(&tmp)?;
    encrypted.execute_batch(&zeroize::Zeroizing::new(format!("PRAGMA key = {};", key_pragma)))?;
    if objects(&encrypted)? != expected {
        return Err(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CORRUPT),
            Some("encrypted copy is incomplete".to_string()),
        ));
    }
    drop(encrypted);

    std::fs::File::open(&tmp).and_then(|f| f.sync_all()).map_err(io)?;
    for suffix in ["-wal", "-shm", "-journal"] {
        wipe_file(&format!("{}{}", path, suffix));
    }
    // A second name for the plain file, so its blocks can be zeroed after the swap (the rename alone only frees them).
    let old = format!("{}.plain-old", path);
    let _ = std::fs::remove_file(&old);
    let linked = std::fs::hard_link(path, &old).is_ok();
    std::fs::rename(&tmp, path).map_err(io)?;
    if let Some(dir) = std::path::Path::new(path).parent() {
        let _ = std::fs::File::open(dir).and_then(|d| d.sync_all());
    }
    if linked {
        wipe_file(&old);
    }
    info!("database encrypted (one-time migration)");
    Ok(())
}

#[cfg(test)]
mod db_encryption_tests {
    use super::*;

    #[test]
    fn plain_db_is_encrypted_once_and_needs_the_key() {
        let dir = std::env::temp_dir().join(format!("typeon-dbenc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("t.db").to_string_lossy().to_string();
        {
            let plain = Connection::open(&path).unwrap();
            plain.execute_batch("PRAGMA journal_mode = WAL; CREATE TABLE t (v TEXT); INSERT INTO t VALUES ('secret-row');").unwrap();
        }
        assert!(is_plain_sqlite(&path));
        let key = db_key_pragma(&[9u8; 32]);
        encrypt_plain_db(&path, &key).unwrap();
        assert!(!is_plain_sqlite(&path));
        assert!(!std::fs::read(&path).unwrap().windows(10).any(|w| w == b"secret-row"));
        assert!(!std::path::Path::new(&format!("{}-wal", path)).exists());
        assert!(!std::path::Path::new(&format!("{}.plain-old", path)).exists());

        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(&format!("PRAGMA key = {};", key.as_str())).unwrap();
        let v: String = conn.query_row("SELECT v FROM t", [], |r| r.get(0)).unwrap();
        assert_eq!(v, "secret-row");

        let wrong = Connection::open(&path).unwrap();
        wrong.execute_batch(&format!("PRAGMA key = {};", db_key_pragma(&[1u8; 32]).as_str())).unwrap();
        assert!(wrong.query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(())).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
