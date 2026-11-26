//! Persistent server store (SQLite, SQLCipher when keyed).
//!
//! ## Two separate stores, deliberately not merged
//!
//! - `mail`: the delivery queue. Sealed envelopes, deleted when the recipient `Ack`s them, at most
//!   `mailbox_ttl_ms` old.
//! - `archive`: history. Mail envelopes cannot be used here. Ratchet message keys are forward-secret and
//!   deleted after use, so last week's envelope cannot be decrypted by anyone today. The archive holds
//!   separate records that the client re-encrypts with its long-lived `archive_key`.
//!
//! Merging the two into one table would be the biggest mistake in this design. A "fetch history from the
//! server" feature would silently return bytes that cannot be decrypted.
//!
//! ## The server cannot decrypt anything
//!
//! Every blob here is encrypted on the client. The structural fields the server sees are kept to a minimum:
//! opaque mailbox and bucket ids, sizes, times and sequence numbers. SECURITY.md documents what these leak.

use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use std::path::Path;

// Note: the package name is `p2p_messenger_core`, but the crate is linked as `p2p_messenger` (see the `[lib] name`
// of that crate). That is why the `use` path differs from the package name.
use p2p_messenger::server_proto::{self, ArchiveRecord, BucketStat, MailItem};

mod enrollments;
mod mail;
mod archive;
mod blobs;

/// State of an enrollment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrollmentState {
    Active,
    Revoked,
}

impl EnrollmentState {
    fn as_str(&self) -> &'static str {
        match self {
            EnrollmentState::Active => "active",
            EnrollmentState::Revoked => "revoked",
        }
    }
    fn parse(s: &str) -> EnrollmentState {
        if s == "revoked" {
            EnrollmentState::Revoked
        } else {
            EnrollmentState::Active
        }
    }
}

/// One enrolled device.
///
/// Fields deliberately NOT here: `device_fingerprint`, `identity_id`, and the device's identity public keys. The
/// server needs only a gate against Sybil registrations (the invite token) and a revocable handle (`enroll_pk`).
/// Asking for more would give the operator a provable list of who uses this server.
#[derive(Debug, Clone)]
pub struct Enrollment {
    pub enrollment_id: Vec<u8>,
    pub enroll_pk: Vec<u8>,
    /// ML-DSA-87 public key. The enrollment signature is verified as hybrid.
    pub enroll_pk_pq: Vec<u8>,
    pub peer_id: String,
    pub state: EnrollmentState,
    pub enrolled_at: i64,
    pub last_seen_at: i64,
    pub bytes_mail: i64,
    pub bytes_archive: i64,
    pub bytes_blob: i64,
}

#[derive(Debug, Clone)]
pub struct BlobState {
    pub blob_id: String,
    pub owner: Vec<u8>,
    pub total_chunks: u32,
    pub received_chunks: u32,
    pub byte_len: i64,
    pub complete: bool,
    /// Blob stride the blob was written with. 0 means the legacy 256 KiB.
    pub chunk_size: u32,
}

pub struct Store {
    conn: Connection,
}

/// Readers of one mailbox that registered with the same proof key: the device a box is the inbound box of, plus room
/// for that device restored under a new enrollment.
///
/// A key-bound box (`server_proto::KEY_BOUND_MAILBOX_PREFIX`: session and relay boxes) accepts only the key its id
/// is derived from, and takes ONE reader (`register_mailboxes_proved`): its sender derives the same key, and as a
/// second reader that never acks it held every row until the TTL. A first-contact box cannot be bound that way, because its
/// sender holds the pairing code, not the reader's key. So it is counted per key, not per box. Anyone who knows a
/// first-contact id (every co-member of a group) can make a proof with a key of its own. A per-box cap, or binding
/// to the first key, would let such a party take the box before the real device and lock that device out. A reader
/// with another key adds a reader. It can never delete a copy that another active reader has not acknowledged
/// (`delete_fully_acked`).
const MAX_READERS_PER_KEY: i64 = 2;

/// A key's full reader slots give up a reader to a newcomer with that key (a restored device) only when that reader
/// has not been seen for this long. The mailbox proof rests on classical X25519 alone, so a quantum attacker could
/// otherwise displace a device still in use. Same horizon as the client's stale-device fan-out filter
/// (`STALE_PEER_RETRY_HORIZON_MS`).
const READER_EVICT_IDLE_MS: i64 = 7 * 24 * 3600 * 1000;

/// Overhead an archive row costs beyond its two peer-sized columns (bucket, ints, owner, primary key, two index
/// entries). Charging only `sealed` and `record_id` would let a 2-byte record cost 2 bytes against a row of about
/// 150 bytes.
const ARCHIVE_ROW_OVERHEAD: usize = 128;

/// The same for a mail row (mailbox id, owner, hashes, three index entries). Charging only `sealed` would let
/// 3-byte items cost 3 bytes against a row of about 250 bytes.
const MAIL_ROW_OVERHEAD: usize = 128;

/// Bytes a mail item is charged against its quota and the server-wide budget.
pub fn mail_row_bytes(mailbox_id: &str, sealed: &[u8]) -> usize {
    sealed.len() + mailbox_id.len() + MAIL_ROW_OVERHEAD
}

/// (mailbox id, hash of the proof key, deposit verifier) of a `MailboxProof` whose signature was verified.
pub type ProvedReader = (String, Vec<u8>, Option<Vec<u8>>);

/// Tests: the deposit secret `register_mailboxes` registers the verifier of.
#[cfg(test)]
pub fn test_secret(mailbox_id: &str) -> [u8; 32] {
    Sha256::digest(mailbox_id.as_bytes()).into()
}

/// Bump on every change to `init_schema`, or existing databases skip the migration.
const SCHEMA_VERSION: i64 = 7;

/// Bytes an archive record is charged against its quota and the server-wide budget.
pub fn archive_row_bytes(rec: &ArchiveRecord) -> usize {
    rec.sealed.len() + rec.record_id.len() + ARCHIVE_ROW_OVERHEAD
}

/// Archive rows not written for this long are swept: 13 months.
pub const ARCHIVE_TTL_MS: i64 = 13 * 30 * 24 * 3600 * 1000;

/// SQLCipher raw key for every later `Store::open`. Unset means plain SQLite (Linux CLI default). The Android app sets
/// it from a random key wrapped by the Keystore, before `startServer`.
static DB_KEY: std::sync::Mutex<Option<zeroize::Zeroizing<[u8; 32]>>> = std::sync::Mutex::new(None);

pub fn set_db_key(key: Option<zeroize::Zeroizing<[u8; 32]>>) {
    *DB_KEY.lock().unwrap_or_else(|p| p.into_inner()) = key;
}

/// Parses a 64-hex-character key (CLI `TYPEON_SERVER_DB_KEY`).
pub fn parse_hex_db_key(hex_key: &str) -> Result<zeroize::Zeroizing<[u8; 32]>, String> {
    let mut key = zeroize::Zeroizing::new([0u8; 32]);
    hex::decode_to_slice(hex_key, &mut key[..]).map_err(|_| "DB key must be 64 hex characters".to_string())?;
    Ok(key)
}

/// Opens `path` with the raw key. Returns an error if the key does not match, or if the linked SQLite has no SQLCipher
/// (a plain build would ignore `PRAGMA key` and silently write plaintext).
fn open_keyed(path: &Path, key: &str) -> Result<Connection, String> {
    let conn = Connection::open(path).map_err(|e| format!("DB could not be opened: {e}"))?;
    let cipher: Option<String> = conn
        .query_row("PRAGMA cipher_version", [], |r| r.get(0))
        .optional()
        .map_err(|e| format!("DB key: {e}"))?;
    if cipher.map_or(true, |v| v.is_empty()) {
        return Err("DB key: SQLite built without SQLCipher".into());
    }
    conn.execute_batch(&zeroize::Zeroizing::new(format!("PRAGMA key = \"x'{key}'\";")))
        .map_err(|e| format!("DB key: {e}"))?;
    conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get::<_, i64>(0))
        .map_err(|e| format!("DB could not be decrypted: {e}"))?;
    Ok(conn)
}

/// One-time migration of a plain database to SQLCipher: `sqlcipher_export` into a new file, verified, then renamed over
/// the old one. No-op when the file is absent or already opens with the key. On any failure the plain database stays
/// in place, and the next open retries.
fn migrate_plain_to_keyed(path: &Path, key: &str) -> Result<(), String> {
    if !path.exists() || open_keyed(path, key).is_ok() {
        return Ok(());
    }
    let err = |e: rusqlite::Error| format!("DB encryption migration: {e}");
    let objects = |c: &Connection| c.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get::<_, i64>(0));
    let tmp = path.with_extension("db.enc");
    for suffix in ["", "-journal", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", tmp.display()));
    }
    let plain = Connection::open(path).map_err(|e| format!("DB could not be opened: {e}"))?;
    let expected = objects(&plain).map_err(|_| "DB opens neither plain nor with this key (wrong key?)".to_string())?;
    // Fold the WAL into the main file and leave WAL mode. A leftover `-wal` next to the encrypted file would be
    // replayed into it.
    let mode: String = plain.query_row("PRAGMA journal_mode = DELETE", [], |r| r.get(0)).map_err(err)?;
    if !mode.eq_ignore_ascii_case("delete") {
        return Err("DB encryption migration: plain database is still in WAL mode".into());
    }
    let user_version: i64 = plain.query_row("PRAGMA user_version", [], |r| r.get(0)).map_err(err)?;
    let tmp_s = tmp.to_string_lossy().replace('\'', "''");
    plain
        .execute_batch(&zeroize::Zeroizing::new(format!("ATTACH DATABASE '{tmp_s}' AS enc KEY \"x'{key}'\";")))
        .map_err(err)?;
    plain.query_row("SELECT sqlcipher_export('enc')", [], |_| Ok(())).map_err(err)?;
    plain
        .execute_batch(&format!("PRAGMA enc.user_version = {user_version}; DETACH DATABASE enc;"))
        .map_err(err)?;
    drop(plain);

    let encrypted = open_keyed(&tmp, key)?;
    if objects(&encrypted).map_err(err)? != expected {
        return Err("DB encryption migration: encrypted copy is incomplete".into());
    }
    drop(encrypted);

    std::fs::File::open(&tmp).and_then(|f| f.sync_all()).map_err(|e| format!("DB encryption migration: {e}"))?;
    for ext in ["db-wal", "db-shm", "db-journal"] {
        let _ = std::fs::remove_file(path.with_extension(ext));
    }
    std::fs::rename(&tmp, path).map_err(|e| format!("DB encryption migration: {e}"))?;
    if let Some(dir) = path.parent() {
        let _ = std::fs::File::open(dir).and_then(|d| d.sync_all());
    }
    Ok(())
}

impl Store {
    pub fn open(db_path: &Path) -> Result<Store, String> {
        let key = DB_KEY.lock().unwrap_or_else(|p| p.into_inner()).clone();
        let key_hex = key.as_ref().map(|k| zeroize::Zeroizing::new(hex::encode(&k[..])));
        let conn = match &key_hex {
            Some(k) => {
                migrate_plain_to_keyed(db_path, k)?;
                open_keyed(db_path, k)?
            }
            None => Connection::open(db_path).map_err(|e| format!("DB could not be opened: {e}"))?,
        };
        // Incremental auto-vacuum, so the file shrinks after mail is acked (see `incremental_vacuum`). It only takes
        // effect before the first table exists, or through one VACUUM. Hence the one-time VACUUM on a database created
        // before this.
        let auto_vacuum: i64 = conn.pragma_query_value(None, "auto_vacuum", |r| r.get(0)).unwrap_or(2);
        if auto_vacuum != 2 {
            let _ = conn.pragma_update(None, "auto_vacuum", 2);
            let _ = conn.execute_batch("VACUUM");
        }
        // WAL: the server is one process, but reads and writes interleave. WAL is also much more durable than the
        // rollback journal on sudden power loss. A volume without WAL support (some SD or exFAT mounts) stays in
        // rollback mode, where the JNI or CLI connection blocks the server. The result is logged below.
        match conn.pragma_update_and_check(None, "journal_mode", "WAL", |r| r.get::<_, String>(0)) {
            Ok(mode) if mode.eq_ignore_ascii_case("wal") => {}
            Ok(mode) => log::warn!("SQLite WAL could not be enabled, journal_mode={mode}: server waits while a second connection writes"),
            Err(e) => log::warn!("SQLite WAL could not be enabled: {e}"),
        }
        // FULL: a `Deposited` answer lets the sender drop its copy, so the mail row must be on disk before that answer,
        // not only in the WAL.
        let _ = conn.pragma_update(None, "synchronous", "FULL");
        // Deleted rows (reader rows, acks, mail) are overwritten with zeros, not left in free pages.
        let _ = conn.pragma_update(None, "secure_delete", "ON");
        // The JNI control surface (`serverStatus`, `joinCode`, `listDevices`, `revokeDevice`) opens a SECOND connection to
        // the same file. WAL resolves most cases, but without `busy_timeout` a conflicting write fails with `SQLITE_BUSY`
        // at once. Many call sites use `let _ =` or `unwrap_or(0)`, so such a failure (a `deposit`, `ack` or
        // `blob_record_chunk`) would be lost without a trace.
        let _ = conn.busy_timeout(std::time::Duration::from_secs(5));
        let store = Store { conn };
        store.init_schema()?;
        Ok(store)
    }

    #[cfg(test)]
    pub fn open_in_memory() -> Result<Store, String> {
        let conn = Connection::open_in_memory().map_err(|e| e.to_string())?;
        let store = Store { conn };
        store.init_schema()?;
        Ok(store)
    }

    /// Schema. Same contract as `init_db` in the core: `CREATE TABLE IF NOT EXISTS`, plus `ALTER TABLE` for columns
    /// added later (only "duplicate column name" is ignored).
    ///
    /// Runs once per `SCHEMA_VERSION`. A database already at this version skips the batch, so a CLI or JNI connection
    /// does not re-run schema writes against the database the daemon is serving.
    fn init_schema(&self) -> Result<(), String> {
        let version: i64 = self.conn.pragma_query_value(None, "user_version", |r| r.get(0)).unwrap_or(0);
        if version == SCHEMA_VERSION {
            return Ok(());
        }
        // Version 7: per-direction inbound boxes and anonymous deposits (protocol 9). Old boxes, readers and mail are
        // keyed to the shared pair boxes and the depositor's enrollment; they are dropped, not migrated. `mail_seq`
        // stays, so a first-contact box (same id as before) keeps counting above old cursors.
        // Told by the columns too: an old DB can carry `user_version` 0 (stamped by nothing, or reset).
        let legacy_mail: bool = self
            .conn
            .query_row("SELECT COUNT(*) FROM pragma_table_info('mail') WHERE name = 'depositor'", [], |r| r.get::<_, i64>(0))
            .map_or(false, |n| n > 0);
        if (version != 0 && version < 7) || legacy_mail {
            self.conn
                .execute_batch("DROP TABLE IF EXISTS mail; DROP TABLE IF EXISTS mail_acks; DROP TABLE IF EXISTS mailbox_readers;
                                DROP TABLE IF EXISTS mailboxes; DROP TABLE IF EXISTS mailbox_keys;")
                .map_err(|e| format!("Schema could not be created: {e}"))?;
        }
        self.conn
            .execute_batch(
                r#"
                CREATE TABLE IF NOT EXISTS enrollments (
                    enrollment_id BLOB PRIMARY KEY,
                    enroll_pk     BLOB NOT NULL,
                    enroll_pk_pq  BLOB NOT NULL DEFAULT x'',
                    peer_id       TEXT NOT NULL,
                    state         TEXT NOT NULL,
                    enrolled_at   INTEGER NOT NULL,
                    last_seen_at  INTEGER NOT NULL,
                    bytes_mail    INTEGER NOT NULL DEFAULT 0,
                    bytes_archive INTEGER NOT NULL DEFAULT 0,
                    bytes_blob    INTEGER NOT NULL DEFAULT 0
                );
                -- Kimlik doğrulaması her istekte Noise'un KANITLADIĞI PeerId
                -- üzerinden yapılıyor, bu yüzden bu arama sıcak yolda.
                CREATE UNIQUE INDEX IF NOT EXISTS idx_enroll_peer ON enrollments(peer_id);

                -- Davet jetonları HASH'lenmiş saklanır: sunucu diski ele
                -- geçse bile henüz kullanılmamış jetonlar kullanılamaz.
                CREATE TABLE IF NOT EXISTS invites (
                    token_hash BLOB PRIMARY KEY,
                    label      TEXT NOT NULL DEFAULT '',
                    uses_left  INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    created_at INTEGER NOT NULL
                );

                -- The challenge is random per connection and taken out of
                -- `ConnState` on use: a table of used ones only grew.
                DROP TABLE IF EXISTS used_challenges;

                -- Who reads a box. A session box has one reader (the device
                -- it is the inbound box of); a first-contact box can have more
                -- (see `MAX_READERS_PER_KEY`). Only a registered reader can
                -- fetch or ack.
                CREATE TABLE IF NOT EXISTS mailbox_readers (
                    mailbox_id   TEXT NOT NULL,
                    owner        BLOB NOT NULL,
                    created_at   INTEGER NOT NULL,
                    last_seen_at INTEGER NOT NULL,
                    -- Hash of the public keys of the `MailboxProof` this
                    -- reader registered with (see `MAX_READERS_PER_KEY`).
                    key_hash     BLOB,
                    -- `server_proto::deposit_verifier` of the box's deposit
                    -- secret. NULL: nobody may deposit for this reader.
                    deposit_verifier BLOB,
                    PRIMARY KEY (mailbox_id, owner)
                );
                CREATE INDEX IF NOT EXISTS idx_reader_owner ON mailbox_readers(owner);

                -- `seq` counts per mailbox (`mail_seq`): a server-global one
                -- let any reader measure the server-wide intake rate.
                CREATE TABLE IF NOT EXISTS mail (
                    id              INTEGER PRIMARY KEY,
                    seq             INTEGER NOT NULL,
                    mailbox_id      TEXT NOT NULL,
                    sealed          BLOB NOT NULL,
                    byte_len        INTEGER NOT NULL,
                    deposited_at_ms INTEGER NOT NULL,
                    expires_at_ms   INTEGER NOT NULL,
                    -- The reader enrollment the item is charged to (the
                    -- depositor is anonymous).
                    owner           BLOB NOT NULL,
                    sealed_hash     BLOB,
                    -- `server_proto::cancel_hash` of the deposit's cancel secret.
                    cancel_hash     BLOB,
                    UNIQUE (mailbox_id, seq)
                );
                -- Last seq handed out per mailbox. Never pruned: a reset
                -- counter would put new mail below a reader's cursor.
                -- ponytail: one small row per mailbox id ever written to.
                CREATE TABLE IF NOT EXISTS mail_seq (mailbox_id TEXT PRIMARY KEY, last INTEGER NOT NULL);
                -- Replaced by `idx_mail_hash` (created below, after the column).
                DROP INDEX IF EXISTS idx_mail_dedup;
                DROP INDEX IF EXISTS idx_mail_fetch;

                -- Per-reader ack cursor. One reader's `Ack` cannot delete mail
                -- for another: a row goes once every active reader acked it
                -- (see `delete_fully_acked`).
                CREATE TABLE IF NOT EXISTS mail_acks (
                    mailbox_id  TEXT NOT NULL,
                    owner       BLOB NOT NULL,
                    through_seq INTEGER NOT NULL,
                    PRIMARY KEY (mailbox_id, owner)
                );

                CREATE TABLE IF NOT EXISTS archive (
                    bucket     TEXT NOT NULL,
                    record_id  TEXT NOT NULL,
                    rev        INTEGER NOT NULL,
                    sent_at_ms INTEGER NOT NULL,
                    sealed     BLOB NOT NULL,
                    byte_len   INTEGER NOT NULL,
                    owner      BLOB NOT NULL,
                    updated_at INTEGER NOT NULL,
                    PRIMARY KEY (bucket, record_id)
                );
                CREATE INDEX IF NOT EXISTS idx_archive_page ON archive(bucket, sent_at_ms DESC);
                CREATE INDEX IF NOT EXISTS idx_archive_owner ON archive(owner, byte_len);

                CREATE TABLE IF NOT EXISTS blobs (
                    blob_id         TEXT PRIMARY KEY,
                    owner           BLOB NOT NULL,
                    total_chunks    INTEGER NOT NULL,
                    received_chunks INTEGER NOT NULL,
                    byte_len        INTEGER NOT NULL,
                    enc_sha256      BLOB,
                    complete        INTEGER NOT NULL DEFAULT 0,
                    created_at      INTEGER NOT NULL,
                    last_served_at  INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_blob_gc ON blobs(complete, last_served_at);
                -- `blob_count` and `recount_blob_bytes` per owner.
                CREATE INDEX IF NOT EXISTS idx_blob_owner ON blobs(owner, byte_len);
                -- Defter #06: parça adımı DOSYA BAŞINA ve istemciden geliyor
                -- (`BlobPut.chunk_size`). Yazarken kullanılıp okurken
                -- unutulursa blob yanlış ofsetlerden servis edilir, o yüzden
                -- blob'la birlikte saklanır.

                -- Hangi parçaların GERÇEKTEN geldiği. Bir sayaç yetmez:
                -- boru hattında parçalar sırasız gelir, o yüzden hangi
                -- indeksin geldiği tek tek tutulur.
                CREATE TABLE IF NOT EXISTS blob_chunks (
                    blob_id     TEXT NOT NULL,
                    chunk_index INTEGER NOT NULL,
                    byte_len    INTEGER NOT NULL,
                    PRIMARY KEY (blob_id, chunk_index)
                );

                -- ENGELLENEN kayıt anahtarları. Hem `revoke` hem `block`
                -- buraya yazar (sahip kararı: iptal = engel): aynı anahtar ve
                -- aynı PeerId taze bir davetle bile kaydolamaz. Anahtarı ve
                -- PeerId'yi yenileyen bir cihaz (yeniden kurulum) geçer; bu
                -- yüzden engel join kodunu da döndürür (bkz. jni `blockDevice`).
                CREATE TABLE IF NOT EXISTS blocked_keys (
                    enroll_pk  BLOB PRIMARY KEY,
                    blocked_at INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v BLOB);
                "#,
            )
            .map_err(|e| format!("Schema could not be created: {e}"))?;
        // SQLite has no `ADD COLUMN IF NOT EXISTS`. Only "duplicate column name" means the column is already there. Any
        // other failure fails init before `user_version` is stamped, so the next start retries.
        let add_column = |sql: &str| -> Result<(), String> {
            match self.conn.execute(sql, []) {
                Err(e) if !e.to_string().contains("duplicate column name") => Err(format!("Schema could not be created ({sql}): {e}")),
                _ => Ok(()),
            }
        };
        add_column("ALTER TABLE blobs ADD COLUMN chunk_size INTEGER NOT NULL DEFAULT 0")?;
        // Hash of the invite the enrollment came in with. The public join code gets a small allowance of active
        // enrollments (see `handle_enroll`).
        add_column("ALTER TABLE enrollments ADD COLUMN invite_hash BLOB")?;
        // `deposit` finds a repeated item through this index alone.
        self.conn
            .execute_batch(
                "CREATE INDEX IF NOT EXISTS idx_mail_hash ON mail(mailbox_id, sealed_hash);
                 CREATE INDEX IF NOT EXISTS idx_mail_expiry ON mail(expires_at_ms);
                 -- Covering: `recount_mail_bytes` and `total_stored_bytes` sum
                 -- from the index and never touch the `sealed` blobs.
                 -- `recount_mail_bytes` checks each row against its owner's ack cursor.
                 DROP INDEX IF EXISTS idx_mail_owner;
                 CREATE INDEX IF NOT EXISTS idx_mail_owner_seq ON mail(owner, mailbox_id, seq, byte_len);
                 -- Covering for `mailbox_usage`, `fetch` and `unacked_for`: no `sealed` read.
                 CREATE INDEX IF NOT EXISTS idx_mail_box ON mail(mailbox_id, seq, byte_len);
                 -- `sweep_expired_archive` reads a range, not the whole table.
                 CREATE INDEX IF NOT EXISTS idx_archive_expiry ON archive(updated_at, owner);",
            )
            .map_err(|e| format!("Schema could not be created: {e}"))?;
        // The dropped mail was charged to its owners: their quota counters start from what is left (nothing).
        self.recount_mail_bytes();
        self.conn
            .pragma_update(None, "user_version", SCHEMA_VERSION)
            .map_err(|e| format!("Schema could not be created: {e}"))?;
        Ok(())
    }

    /// Total bytes the server currently stores (mail, archive and blobs). This is the global ceiling on top of the
    /// per-record quotas (see `total_budget_exceeded`).
    pub fn total_stored_bytes(&self) -> i64 {
        self.conn
            .query_row(
                "SELECT COALESCE((SELECT SUM(byte_len) FROM mail), 0)
                      + COALESCE((SELECT SUM(byte_len) FROM archive), 0)
                      + COALESCE((SELECT SUM(byte_len) FROM blobs), 0)",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0)
    }

    // -----------------------------------------------------------------
    // Meta
    // -----------------------------------------------------------------

    pub fn meta_get(&self, key: &str) -> Option<Vec<u8>> {
        self.conn
            .query_row("SELECT v FROM meta WHERE k = ?1", params![key], |r| r.get(0))
            .optional()
            .ok()
            .flatten()
    }

    pub fn meta_set(&self, key: &str, value: &[u8]) -> Result<(), String> {
        self.conn
            .execute("INSERT OR REPLACE INTO meta (k, v) VALUES (?1, ?2)", params![key, value])
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// The wall clock stepped forward by `shift` and the step was accepted:
    /// every deadline stamped on the old clock (at or before `upto`) moves
    /// with it, so it keeps the time it had left. Without this a corrected
    /// clock expired all mail, blobs and idle enrollments in one sweep.
    pub fn shift_deadlines(&self, shift: i64, upto: i64) {
        let Ok(tx) = self.conn.unchecked_transaction() else { return };
        let _ = self.conn.execute(
            "UPDATE mail SET expires_at_ms = expires_at_ms + ?1 WHERE deposited_at_ms <= ?2",
            params![shift, upto],
        );
        let _ = self.conn.execute(
            "UPDATE blobs SET last_served_at = last_served_at + ?1 WHERE last_served_at <= ?2",
            params![shift, upto],
        );
        let _ = self.conn.execute(
            "UPDATE blobs SET created_at = created_at + ?1 WHERE created_at <= ?2",
            params![shift, upto],
        );
        let _ = self.conn.execute(
            "UPDATE enrollments SET last_seen_at = last_seen_at + ?1 WHERE last_seen_at <= ?2",
            params![shift, upto],
        );
        let _ = self.conn.execute(
            "UPDATE archive SET updated_at = updated_at + ?1 WHERE updated_at <= ?2",
            params![shift, upto],
        );
        let _ = tx.commit();
    }

    /// Rows stamped before `floor` were stamped by a clock that was wrong
    /// (a phone booted with a 1970/2020 RTC, then restarted with the right
    /// time): they are dated `now`, keeping their TTL length.
    pub fn restamp_before(&self, floor: i64, now: i64) {
        let Ok(tx) = self.conn.unchecked_transaction() else { return };
        let _ = self.conn.execute(
            "UPDATE mail SET expires_at_ms = ?2 + (expires_at_ms - deposited_at_ms), deposited_at_ms = ?2
             WHERE deposited_at_ms < ?1",
            params![floor, now],
        );
        let _ = self.conn.execute("UPDATE blobs SET last_served_at = ?2 WHERE last_served_at < ?1", params![floor, now]);
        let _ = self.conn.execute("UPDATE blobs SET created_at = ?2 WHERE created_at < ?1", params![floor, now]);
        let _ = self.conn.execute("UPDATE enrollments SET last_seen_at = ?2 WHERE last_seen_at < ?1", params![floor, now]);
        let _ = self.conn.execute("UPDATE archive SET updated_at = ?2 WHERE updated_at < ?1", params![floor, now]);
        let _ = tx.commit();
    }

    /// Changes whenever ANOTHER connection (the CLI, the JNI side) commits.
    pub fn data_version(&self) -> i64 {
        self.conn.query_row("PRAGMA data_version", [], |r| r.get(0)).unwrap_or(-1)
    }

    /// Returns freed pages to the filesystem (see `open`).
    pub fn incremental_vacuum(&self) {
        let _ = self.conn.execute_batch("PRAGMA incremental_vacuum;");
    }
}

#[cfg(test)]
mod tests;
