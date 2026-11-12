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

/// Readers of one mailbox that registered with the same proof key: both ends of a session, or the one device of a
/// first-contact box.
///
/// A key-bound box (`server_proto::KEY_BOUND_MAILBOX_PREFIX`: session and relay boxes) accepts only the key its id
/// is derived from, so there the cap applies per box. A first-contact box cannot be bound that way, because its
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
/// entries). Charging only `sealed` and `record_id` let a 2-byte record cost 2 bytes against a row of about 150 bytes.
const ARCHIVE_ROW_OVERHEAD: usize = 128;

/// The same for a mail row (mailbox id, depositor, hash, three index entries). Charging only `sealed` let 3-byte
/// items cost 3 bytes against a row of about 250 bytes.
const MAIL_ROW_OVERHEAD: usize = 128;

/// Bytes a mail item is charged against its quota and the server-wide budget.
pub fn mail_row_bytes(mailbox_id: &str, sealed: &[u8]) -> usize {
    sealed.len() + mailbox_id.len() + MAIL_ROW_OVERHEAD
}

/// Bump on every change to `init_schema`, or existing databases skip the migration.
const SCHEMA_VERSION: i64 = 5;

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
    hex::decode_to_slice(hex_key, &mut key[..]).map_err(|_| "DB anahtarı 64 hex karakter olmalı".to_string())?;
    Ok(key)
}

/// Opens `path` with the raw key. Returns an error if the key does not match, or if the linked SQLite has no SQLCipher
/// (a plain build would ignore `PRAGMA key` and silently write plaintext).
fn open_keyed(path: &Path, key: &str) -> Result<Connection, String> {
    let conn = Connection::open(path).map_err(|e| format!("DB açılamadı: {e}"))?;
    let cipher: Option<String> = conn
        .query_row("PRAGMA cipher_version", [], |r| r.get(0))
        .optional()
        .map_err(|e| format!("DB anahtarı: {e}"))?;
    if cipher.map_or(true, |v| v.is_empty()) {
        return Err("DB anahtarı: SQLite SQLCipher olmadan derlenmiş".into());
    }
    conn.execute_batch(&zeroize::Zeroizing::new(format!("PRAGMA key = \"x'{key}'\";")))
        .map_err(|e| format!("DB anahtarı: {e}"))?;
    conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get::<_, i64>(0))
        .map_err(|e| format!("DB şifre çözülemedi: {e}"))?;
    Ok(conn)
}

/// One-time migration of a plain database to SQLCipher: `sqlcipher_export` into a new file, verified, then renamed over
/// the old one. No-op when the file is absent or already opens with the key. On any failure the plain database stays
/// in place, and the next open retries.
fn migrate_plain_to_keyed(path: &Path, key: &str) -> Result<(), String> {
    if !path.exists() || open_keyed(path, key).is_ok() {
        return Ok(());
    }
    let err = |e: rusqlite::Error| format!("DB şifreleme geçişi: {e}");
    let objects = |c: &Connection| c.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get::<_, i64>(0));
    let tmp = path.with_extension("db.enc");
    for suffix in ["", "-journal", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", tmp.display()));
    }
    let plain = Connection::open(path).map_err(|e| format!("DB açılamadı: {e}"))?;
    let expected = objects(&plain).map_err(|_| "DB ne düz ne de bu anahtarla açılıyor (yanlış anahtar?)".to_string())?;
    // Fold the WAL into the main file and leave WAL mode. A leftover `-wal` next to the encrypted file would be
    // replayed into it.
    let mode: String = plain.query_row("PRAGMA journal_mode = DELETE", [], |r| r.get(0)).map_err(err)?;
    if !mode.eq_ignore_ascii_case("delete") {
        return Err("DB şifreleme geçişi: plain database is still in WAL mode".into());
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
        return Err("DB şifreleme geçişi: encrypted copy is incomplete".into());
    }
    drop(encrypted);

    std::fs::File::open(&tmp).and_then(|f| f.sync_all()).map_err(|e| format!("DB şifreleme geçişi: {e}"))?;
    for ext in ["db-wal", "db-shm", "db-journal"] {
        let _ = std::fs::remove_file(path.with_extension(ext));
    }
    std::fs::rename(&tmp, path).map_err(|e| format!("DB şifreleme geçişi: {e}"))?;
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
            None => Connection::open(db_path).map_err(|e| format!("DB açılamadı: {e}"))?,
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
        // rollback journal on sudden power loss. A volume without WAL support (some SD or exFAT mounts) silently stays
        // in rollback mode, where the JNI or CLI connection blocks the server.
        match conn.pragma_update_and_check(None, "journal_mode", "WAL", |r| r.get::<_, String>(0)) {
            Ok(mode) if mode.eq_ignore_ascii_case("wal") => {}
            Ok(mode) => log::warn!("SQLite WAL açılamadı, journal_mode={mode}: ikinci bağlantı yazarken sunucu bekler"),
            Err(e) => log::warn!("SQLite WAL açılamadı: {e}"),
        }
        // FULL: a `Deposited` answer lets the sender drop its copy, so the mail row must be on disk before that answer,
        // not only in the WAL.
        let _ = conn.pragma_update(None, "synchronous", "FULL");
        // Deleted rows (reader rows, acks, mail) are overwritten with zeros, not left in free pages.
        let _ = conn.pragma_update(None, "secure_delete", "ON");
        // The JNI control surface (`serverStatus`, `joinCode`, `listDevices`, `revokeDevice`) opens a SECOND connection to
        // the same file. WAL resolves most cases, but without `busy_timeout` conflicting writes returned `SQLITE_BUSY`
        // at once. Nearly all call sites use `let _ =` or `unwrap_or(0)`, so a failed `deposit`, `ack` or
        // `blob_record_chunk` was swallowed silently.
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
    /// Runs once per `SCHEMA_VERSION`. Previously every CLI or JNI open re-ran the whole batch, writes included,
    /// against the database the daemon was serving.
    fn init_schema(&self) -> Result<(), String> {
        let version: i64 = self.conn.pragma_query_value(None, "user_version", |r| r.get(0)).unwrap_or(0);
        if version == SCHEMA_VERSION {
            return Ok(());
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

                CREATE TABLE IF NOT EXISTS mailboxes (
                    mailbox_id   TEXT PRIMARY KEY,
                    owner        BLOB NOT NULL,
                    created_at   INTEGER NOT NULL,
                    last_seen_at INTEGER NOT NULL
                );

                -- Defter #03: bir kutunun TEK sahibi YOK — bir ratchet
                -- kutusunu iki taraf da hem yazar hem okur (kutu kimliği
                -- ortak kök anahtardan türüyor, bkz. `server_seal::
                -- server_mailbox_id`), o yüzden `mailboxes.mailbox_id`
                -- birincil anahtarı yanlış modeldi. Erişim kontrolü artık
                -- "bu kutuyu KAYDETMİŞ miydin" sorusu: kaydetmemiş bir
                -- istemci ne okuyabilir ne silebilir.
                CREATE TABLE IF NOT EXISTS mailbox_readers (
                    mailbox_id   TEXT NOT NULL,
                    owner        BLOB NOT NULL,
                    created_at   INTEGER NOT NULL,
                    last_seen_at INTEGER NOT NULL,
                    -- Hash of the public keys of the `MailboxProof` this
                    -- reader registered with (see `MAX_READERS_PER_KEY`).
                    key_hash     BLOB,
                    PRIMARY KEY (mailbox_id, owner)
                );
                CREATE INDEX IF NOT EXISTS idx_reader_owner ON mailbox_readers(owner);

                -- Mevcut kurulumlardan tek seferlik taşıma (idempotent).
                INSERT OR IGNORE INTO mailbox_readers (mailbox_id, owner, created_at, last_seen_at)
                    SELECT mailbox_id, owner, created_at, last_seen_at FROM mailboxes;
                DELETE FROM mailboxes;

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
                    depositor       BLOB NOT NULL,
                    sealed_hash     BLOB,
                    UNIQUE (mailbox_id, seq)
                );
                -- Last seq handed out per mailbox. Never pruned: a reset
                -- counter would put new mail below a reader's cursor.
                -- ponytail: one small row per mailbox id ever written to.
                CREATE TABLE IF NOT EXISTS mail_seq (mailbox_id TEXT PRIMARY KEY, last INTEGER NOT NULL);
                -- Replaced by `idx_mail_hash` (created below, after the column).
                DROP INDEX IF EXISTS idx_mail_dedup;
                DROP INDEX IF EXISTS idx_mail_fetch;

                -- Okuyucu başına onay imleci. Kayıt herkese açık olduğundan
                -- (ilk-temas kutusunun kimliği cihaz parmak izinden türüyor),
                -- tek bir okuyucunun `Ack`'i postayı başkaları için SİLEMEZ:
                -- satır ancak bırakan dışındaki bütün okuyucular onaylayınca
                -- gider (bkz. `delete_fully_acked`).
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

                -- Hangi parçaların GERÇEKTEN geldiği. Önceden sadece bir
                -- sayaç vardı ve bu, parçaların KESİN OLARAK sırayla
                -- gelmesini şart koşuyordu — yani aynı anda tek parça
                -- havada olabiliyordu ve hız `parça/gidiş-dönüş` ile
                -- sınırlıydı. Boru hattında parçalar sırasız gelir, o yüzden
                -- sayaç yetmez: hangi indeksin geldiği tek tek tutulmalı.
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
            .map_err(|e| format!("Şema oluşturulamadı: {e}"))?;
        // SQLite has no `ADD COLUMN IF NOT EXISTS`. Only "duplicate column name" means the column is already there. Any
        // other failure fails init before `user_version` is stamped, so the next start retries.
        let add_column = |sql: &str| -> Result<(), String> {
            match self.conn.execute(sql, []) {
                Err(e) if !e.to_string().contains("duplicate column name") => Err(format!("Şema oluşturulamadı ({sql}): {e}")),
                _ => Ok(()),
            }
        };
        add_column("ALTER TABLE blobs ADD COLUMN chunk_size INTEGER NOT NULL DEFAULT 0")?;
        add_column("ALTER TABLE mail ADD COLUMN sealed_hash BLOB")?;
        // Hash of the invite the enrollment came in with. The public join code gets a small allowance of active
        // enrollments (see `handle_enroll`).
        add_column("ALTER TABLE enrollments ADD COLUMN invite_hash BLOB")?;
        // The global AUTOINCREMENT `seq` becomes per mailbox. Old rows keep their seq. New rows start above the old
        // high-water mark (`mail_seq_base`), so no client cursor ends up above new mail.
        let old_mail: bool = self
            .conn
            .query_row("SELECT sql LIKE '%AUTOINCREMENT%' FROM sqlite_master WHERE type = 'table' AND name = 'mail'", [], |r| r.get(0))
            .map_err(|e| format!("Şema oluşturulamadı: {e}"))?;
        if old_mail {
            self.conn
                .execute_batch(
                    "BEGIN;
                     INSERT OR REPLACE INTO meta (k, v) VALUES ('mail_seq_base',
                         MAX(COALESCE((SELECT seq FROM sqlite_sequence WHERE name = 'mail'), 0),
                             COALESCE((SELECT MAX(seq) FROM mail), 0)));
                     CREATE TABLE mail_new (
                         id INTEGER PRIMARY KEY, seq INTEGER NOT NULL, mailbox_id TEXT NOT NULL,
                         sealed BLOB NOT NULL, byte_len INTEGER NOT NULL, deposited_at_ms INTEGER NOT NULL,
                         expires_at_ms INTEGER NOT NULL, depositor BLOB NOT NULL, sealed_hash BLOB,
                         UNIQUE (mailbox_id, seq));
                     INSERT INTO mail_new (id, seq, mailbox_id, sealed, byte_len, deposited_at_ms, expires_at_ms, depositor, sealed_hash)
                         SELECT seq, seq, mailbox_id, sealed, byte_len, deposited_at_ms, expires_at_ms, depositor, sealed_hash FROM mail;
                     DROP TABLE mail;
                     ALTER TABLE mail_new RENAME TO mail;
                     COMMIT;",
                )
                .map_err(|e| format!("Şema oluşturulamadı: {e}"))?;
        }
        // The per-mailbox key binding becomes a per-reader key. Each reader keeps the key its box was bound to, then
        // the binding table is dropped.
        add_column("ALTER TABLE mailbox_readers ADD COLUMN key_hash BLOB")?;
        let _ = self.conn.execute(
            "UPDATE mailbox_readers SET key_hash = (SELECT k.key_hash FROM mailbox_keys k
                                                    WHERE k.mailbox_id = mailbox_readers.mailbox_id)
             WHERE key_hash IS NULL",
            [],
        );
        let _ = self.conn.execute("DROP TABLE IF EXISTS mailbox_keys", []);
        // `deposit` finds a repeated item through this index alone.
        self.conn
            .execute_batch(
                "CREATE INDEX IF NOT EXISTS idx_mail_hash ON mail(mailbox_id, depositor, sealed_hash);
                 CREATE INDEX IF NOT EXISTS idx_mail_expiry ON mail(expires_at_ms);
                 -- Covering: `recount_mail_bytes` and `total_stored_bytes` sum
                 -- from the index and never touch the `sealed` blobs.
                 CREATE INDEX IF NOT EXISTS idx_mail_depositor ON mail(depositor, byte_len);",
            )
            .map_err(|e| format!("Şema oluşturulamadı: {e}"))?;
        self.conn
            .pragma_update(None, "user_version", SCHEMA_VERSION)
            .map_err(|e| format!("Şema oluşturulamadı: {e}"))?;
        Ok(())
    }

    /// See the note on the upload stride: it is fixed by the first chunk.
    pub fn blob_set_chunk_size(&self, blob_id: &str, chunk_size: u32) {
        let _ = self.conn.execute(
            "UPDATE blobs SET chunk_size = ?2 WHERE blob_id = ?1 AND chunk_size = 0",
            params![blob_id, chunk_size as i64],
        );
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

    // -----------------------------------------------------------------
    // Invites and enrollment
    // -----------------------------------------------------------------

    /// Creates an invite. `uses <= 0` means UNLIMITED (stored as `-1`).
    ///
    /// Requirement: several people must be able to join from one QR code or link. Before, each new person needed the
    /// operator to send the server a fresh code. Invites were single-use, and the Android server UI pinned them to
    /// `uses=1`. An unlimited invite can be published once (poster, message, web page) and then anyone can join on
    /// their own. The Sybil gate is not lost, it MOVES: the token itself no longer gates, the hourly enrollment cap in
    /// `ServerCore::handle_enroll` (`MAX_PUBLIC_ENROLLMENTS_PER_HOUR`) does, and the operator can rotate the code at
    /// any time (`rotate_join_code`).
    pub fn create_invite(&self, token_hash: &[u8], label: &str, uses: i64, expires_at: i64, now: i64) -> Result<(), String> {
        let uses = if uses <= 0 { -1 } else { uses };
        self.conn
            .execute(
                "INSERT OR REPLACE INTO invites (token_hash, label, uses_left, expires_at, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![token_hash, label, uses, expires_at, now],
            )
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// Deletes an invite. `rotate_join_code` uses it to invalidate the old public code.
    pub fn delete_invite(&self, token_hash: &[u8]) -> Result<(), String> {
        self.conn
            .execute("DELETE FROM invites WHERE token_hash = ?1", params![token_hash])
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// Remaining uses: `Some(-1)` unlimited, `Some(0)` used up, `None` no such invite, or it has expired.
    pub fn invite_uses_left(&self, token_hash: &[u8], now: i64) -> Option<i64> {
        self.conn
            .query_row(
                "SELECT uses_left FROM invites WHERE token_hash = ?1 AND (expires_at = 0 OR expires_at > ?2)",
                params![token_hash, now],
                |r| r.get(0),
            )
            .optional()
            .ok()
            .flatten()
    }

    /// Enrollments opened in (`since`, `now`]: the public code's hourly cap. Rows dated after `now` (the clock was
    /// stepped back) are not counted. They once froze the cap until the clock caught up.
    pub fn count_enrollments_since(&self, since: i64, now: i64) -> i64 {
        self.conn
            .query_row(
                "SELECT COUNT(*) FROM enrollments WHERE enrolled_at > ?1 AND enrolled_at <= ?2",
                params![since, now],
                |r| r.get(0),
            )
            .unwrap_or(0)
    }

    /// Active enrollments seen at or after `idle_before`. A sleeping one (see `sleep_idle_enrollments`) holds no place
    /// under the cap.
    pub fn count_active_enrollments(&self, idle_before: i64) -> i64 {
        self.conn
            .query_row(
                "SELECT COUNT(*) FROM enrollments WHERE state = 'active' AND last_seen_at >= ?1",
                params![idle_before],
                |r| r.get(0),
            )
            .unwrap_or(0)
    }

    /// Active, non-idle enrollments that came in with this invite.
    pub fn count_active_enrollments_via(&self, token_hash: &[u8], idle_before: i64) -> i64 {
        self.conn
            .query_row(
                "SELECT COUNT(*) FROM enrollments WHERE state = 'active' AND last_seen_at >= ?1 AND invite_hash = ?2",
                params![idle_before, token_hash],
                |r| r.get(0),
            )
            .unwrap_or(0)
    }

    /// Puts active enrollments last seen before `before` to sleep: their
    /// reader rows go, and mail in boxes nobody reads any more goes with them.
    /// The row, its key and its quota counters stay, so the device comes back
    /// with `Rebind` (or its old PeerId), which refreshes `last_seen_at`.
    /// Returns the mail rows removed; the caller recounts the depositors.
    pub fn sleep_idle_enrollments(&self, before: i64) -> usize {
        let sleepers = "SELECT enrollment_id FROM enrollments WHERE state = 'active' AND last_seen_at < ?1";
        let Ok(tx) = self.conn.unchecked_transaction() else { return 0 };
        // Mail stays while any reader that is awake still has the box.
        let removed = self
            .conn
            .execute(
                &format!(
                    "DELETE FROM mail WHERE mailbox_id IN (SELECT mailbox_id FROM mailbox_readers WHERE owner IN ({sleepers}))
                       AND NOT EXISTS (SELECT 1 FROM mailbox_readers r
                                       WHERE r.mailbox_id = mail.mailbox_id AND r.owner NOT IN ({sleepers})
                                         AND r.owner != mail.depositor
                                         AND r.owner IN (SELECT enrollment_id FROM enrollments WHERE state = 'active'))"
                ),
                params![before],
            )
            .unwrap_or(0);
        let _ = self.conn.execute(&format!("DELETE FROM mailbox_readers WHERE owner IN ({sleepers})"), params![before]);
        let _ = tx.commit();
        removed
    }

    pub fn list_invites(&self, now: i64) -> Vec<(String, i64, i64, bool)> {
        let mut stmt = match self.conn.prepare("SELECT label, uses_left, expires_at FROM invites ORDER BY created_at DESC") {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let rows = stmt.query_map([], |r| {
            let label: String = r.get(0)?;
            // `uses_left` is now a signed value: `-1` means unlimited (see `create_invite`). Converting it to `u32`
            // would turn it into about 4 billion.
            let uses: i64 = r.get(1)?;
            let exp: i64 = r.get(2)?;
            Ok((label, uses, exp, uses != 0 && (exp == 0 || exp > now)))
        });
        rows.map(|it| it.filter_map(|r| r.ok()).collect()).unwrap_or_default()
    }

    /// Consumes one use of an invite. Returns `true` if it was valid.
    ///
    /// Decrementing the use counter and creating the enrollment must happen in the SAME call chain. Otherwise two
    /// concurrent `Enroll` requests could spend a single-use token twice. `UPDATE ... WHERE uses_left > 0` is one
    /// atomic statement, so the race is closed at the SQLite level.
    pub fn consume_invite(&self, token_hash: &[u8], now: i64) -> Result<bool, String> {
        let changed = self
            .conn
            .execute(
                // `uses_left = -1` is UNLIMITED: consumed but not decremented (see `create_invite`). The `<> 0` check
                // separates used-up (0) from unlimited (-1) in one expression.
                "UPDATE invites SET uses_left = CASE WHEN uses_left < 0 THEN uses_left ELSE uses_left - 1 END
                 WHERE token_hash = ?1 AND uses_left <> 0 AND (expires_at = 0 OR expires_at > ?2)",
                params![token_hash, now],
            )
            .map_err(|e| e.to_string())?;
        Ok(changed > 0)
    }

    /// Consumes one invite use and writes the enrollment: both or neither. `Ok(false)`: the invite is spent, expired
    /// or gone.
    pub fn enroll_with_invite(&self, token_hash: &[u8], now: i64, e: &Enrollment) -> Result<bool, String> {
        let tx = self.conn.unchecked_transaction().map_err(|e| e.to_string())?;
        if !self.consume_invite(token_hash, now)? {
            return Ok(false);
        }
        self.insert_enrollment(e)?;
        self.conn
            .execute("UPDATE enrollments SET invite_hash = ?1 WHERE enrollment_id = ?2", params![token_hash, e.enrollment_id])
            .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(true)
    }

    pub fn insert_enrollment(&self, e: &Enrollment) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO enrollments
                 (enrollment_id, enroll_pk, enroll_pk_pq, peer_id, state, enrolled_at, last_seen_at, bytes_mail, bytes_archive, bytes_blob)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    e.enrollment_id, e.enroll_pk, e.enroll_pk_pq, e.peer_id, e.state.as_str(),
                    e.enrolled_at, e.last_seen_at, e.bytes_mail, e.bytes_archive, e.bytes_blob
                ],
            )
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    pub fn enrollment_by_peer(&self, peer_id: &str) -> Option<Enrollment> {
        self.row_to_enrollment("SELECT enrollment_id, enroll_pk, enroll_pk_pq, peer_id, state, enrolled_at, last_seen_at, bytes_mail, bytes_archive, bytes_blob FROM enrollments WHERE peer_id = ?1", peer_id)
    }

    pub fn enrollment_by_id(&self, enrollment_id: &[u8]) -> Option<Enrollment> {
        self.conn
            .query_row(
                "SELECT enrollment_id, enroll_pk, enroll_pk_pq, peer_id, state, enrolled_at, last_seen_at, bytes_mail, bytes_archive, bytes_blob FROM enrollments WHERE enrollment_id = ?1",
                params![enrollment_id],
                Self::map_enrollment,
            )
            .optional()
            .ok()
            .flatten()
    }

    fn row_to_enrollment(&self, sql: &str, key: &str) -> Option<Enrollment> {
        self.conn
            .query_row(sql, params![key], Self::map_enrollment)
            .optional()
            .ok()
            .flatten()
    }

    fn map_enrollment(r: &rusqlite::Row) -> rusqlite::Result<Enrollment> {
        let state: String = r.get(4)?;
        Ok(Enrollment {
            enrollment_id: r.get(0)?,
            enroll_pk: r.get(1)?,
            enroll_pk_pq: r.get(2)?,
            peer_id: r.get(3)?,
            state: EnrollmentState::parse(&state),
            enrolled_at: r.get(5)?,
            last_seen_at: r.get(6)?,
            bytes_mail: r.get(7)?,
            bytes_archive: r.get(8)?,
            bytes_blob: r.get(9)?,
        })
    }

    /// `Rebind`: moves an existing enrollment to a new `PeerId`.
    pub fn rebind_enrollment(&self, enrollment_id: &[u8], new_peer_id: &str, now: i64) -> Result<(), String> {
        // If ANOTHER enrollment is already bound to the same PeerId, release it first. `peer_id` is UNIQUE, and the
        // INSERT would otherwise collide (a reinstalled device can regenerate the same libp2p key). The placeholder is
        // unique per row: a shared '' broke the index on the second collision. One transaction: a failed second UPDATE
        // would leave the device unbound.
        let tx = self.conn.unchecked_transaction().map_err(|e| e.to_string())?;
        self.conn
            .execute(
                "UPDATE enrollments SET peer_id = 'unbound:' || hex(enrollment_id) WHERE peer_id = ?1 AND enrollment_id != ?2",
                params![new_peer_id, enrollment_id],
            )
            .map_err(|e| e.to_string())?;
        let n = self
            .conn
            .execute(
                "UPDATE enrollments SET peer_id = ?1, last_seen_at = ?2 WHERE enrollment_id = ?3",
                params![new_peer_id, now, enrollment_id],
            )
            .map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("Kayıt bulunamadı".to_string());
        }
        tx.commit().map_err(|e| e.to_string())
    }

    /// Revoke is a block: the enroll key goes on the block list, and the row stays. So `handle_enroll` finds the
    /// blocked key for this PeerId too.
    pub fn revoke_enrollment(&self, enrollment_id: &[u8]) -> Result<(), String> {
        // One transaction: a blocked key with the row still 'active' would leave the device fully served.
        let tx = self.conn.unchecked_transaction().map_err(|e| e.to_string())?;
        self.conn
            .execute(
                "INSERT OR REPLACE INTO blocked_keys (enroll_pk, blocked_at)
                 SELECT enroll_pk, CAST(strftime('%s','now') AS INTEGER) * 1000 FROM enrollments WHERE enrollment_id = ?1",
                params![enrollment_id],
            )
            .map_err(|e| e.to_string())?;
        self.conn
            .execute("UPDATE enrollments SET state = 'revoked' WHERE enrollment_id = ?1", params![enrollment_id])
            .map_err(|e| e.to_string())
            .and_then(|n| if n == 0 { Err("Kayıt bulunamadı".to_string()) } else { Ok(()) })?;
        tx.commit().map_err(|e| e.to_string())
    }

    pub fn list_enrollments(&self) -> Vec<Enrollment> {
        let mut stmt = match self.conn.prepare(
            "SELECT enrollment_id, enroll_pk, enroll_pk_pq, peer_id, state, enrolled_at, last_seen_at, bytes_mail, bytes_archive, bytes_blob FROM enrollments ORDER BY enrolled_at",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        stmt.query_map([], Self::map_enrollment)
            .map(|it| it.filter_map(|r| r.ok()).collect())
            .unwrap_or_default()
    }

    pub fn touch_enrollment(&self, enrollment_id: &[u8], now: i64) {
        let _ = self.conn.execute(
            "UPDATE enrollments SET last_seen_at = ?1 WHERE enrollment_id = ?2",
            params![now, enrollment_id],
        );
    }

    // -----------------------------------------------------------------
    // Mailbox
    // -----------------------------------------------------------------

    /// Tests: every id comes with a proof made by one shared key.
    #[cfg(test)]
    pub fn register_mailboxes(&self, owner: &[u8], add: &[String], drop: &[String], now: i64, max: u32) -> Result<Vec<String>, String> {
        let proofs: Vec<(String, Vec<u8>)> = add.iter().map(|id| (id.clone(), b"test-key".to_vec())).collect();
        self.register_mailboxes_proved(owner, add, drop, &proofs, now, max).map(|(refused, _)| refused)
    }

    /// Returns `Ok` with the ids of `add` that were refused (mailbox quota, or the proof key's reader slots full and
    /// in use), and then the ids that need a proof but came without one. The other ids are registered. One refused id
    /// does not cost the batch.
    ///
    /// `proofs`: (mailbox id, hash of the mailbox key) for each `MailboxProof` whose signature the caller verified. An
    /// id the owner already reads needs none. A new reader row keeps its proof key (`MAX_READERS_PER_KEY`).
    pub fn register_mailboxes_proved(
        &self,
        owner: &[u8],
        add: &[String],
        drop: &[String],
        proofs: &[(String, Vec<u8>)],
        now: i64,
        max: u32,
    ) -> Result<(Vec<String>, Vec<String>), String> {
        // One transaction: an eviction without the newcomer's row would lose a reader.
        let tx = self.conn.unchecked_transaction().map_err(|e| e.to_string())?;
        let mut refused = Vec::new();
        let mut unproven = Vec::new();
        // Counted once, then kept up to date below. A query per id scanned the owner's rows for every id.
        let mut count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM mailbox_readers WHERE owner = ?1", params![owner], |r| r.get(0))
            .unwrap_or(0);
        for id in add {
            // If already registered, skip the counter check. The call must be idempotent.
            //
            // Found during review: the query did NOT filter by `owner`, but `mailbox_readers` is multi-reader (see the
            // schema note). So a box another party registered counted as "already there" for this client too, and the
            // `max_mailboxes` quota was skipped. Both sides of a ratchet box register it, so this is the NORMAL case,
            // not an edge case. In practice the quota was never enforced on the second side.
            let exists: bool = self
                .conn
                .query_row(
                    "SELECT 1 FROM mailbox_readers WHERE mailbox_id = ?1 AND owner = ?2",
                    params![id, owner],
                    |_| Ok(true),
                )
                .optional()
                .ok()
                .flatten()
                .unwrap_or(false);
            if !exists && count >= max as i64 {
                refused.push(id.clone());
                continue;
            }
            // A new reader needs a proof. There is at most `MAX_READERS_PER_KEY` readers per proof key, so one key cannot
            // fill another's slots.
            let mut reader_key: Option<&Vec<u8>> = None;
            if !exists {
                let Some((_, key_hash)) = proofs.iter().find(|(m, _)| m == id) else {
                    unproven.push(id.clone());
                    continue;
                };
                // A key-bound id has exactly one key, the one it is derived from. Knowing the id is not enough to read the box.
                if id.starts_with(server_proto::KEY_BOUND_MAILBOX_PREFIX) && *id != server_proto::key_bound_mailbox_id(key_hash) {
                    refused.push(id.clone());
                    continue;
                }
                reader_key = Some(key_hash);
                let readers: i64 = self
                    .conn
                    .query_row(
                        "SELECT COUNT(*) FROM mailbox_readers WHERE mailbox_id = ?1 AND key_hash = ?2",
                        params![id, key_hash],
                        |r| r.get(0),
                    )
                    .unwrap_or(0);
                // The slots of this key are full. The newcomer holds the same secret, so it is one of those ends (a restored
                // device under a new enrollment). The same-key reader seen longest ago makes room, but only once it has been
                // idle for `READER_EVICT_IDLE_MS` (its own requests or its last Register). A reader in use is never displaced.
                if readers >= MAX_READERS_PER_KEY {
                    let stale: Option<(Vec<u8>, i64)> = self
                        .conn
                        .query_row(
                            "SELECT r.owner, MAX(r.last_seen_at, COALESCE(e.last_seen_at, 0)) AS seen
                               FROM mailbox_readers r LEFT JOIN enrollments e ON e.enrollment_id = r.owner
                              WHERE r.mailbox_id = ?1 AND r.key_hash = ?2 ORDER BY seen ASC LIMIT 1",
                            params![id, key_hash],
                            |r| Ok((r.get(0)?, r.get(1)?)),
                        )
                        .optional()
                        .map_err(|e| e.to_string())?;
                    let Some((stale, _)) = stale.filter(|(_, seen)| now - seen >= READER_EVICT_IDLE_MS) else {
                        refused.push(id.clone());
                        continue;
                    };
                    let _ = self
                        .conn
                        .execute("DELETE FROM mailbox_readers WHERE mailbox_id = ?1 AND owner = ?2", params![id, stale]);
                    let _ = self
                        .conn
                        .execute("DELETE FROM mail_acks WHERE mailbox_id = ?1 AND owner = ?2", params![id, stale]);
                    let _ = self.delete_fully_acked(id);
                }
            }
            // The record is now MULTI-READER (see the `mailbox_readers` schema note). Both sides of a ratchet box register
            // it, and one registration does not overwrite the other. A reader keeps its key.
            self.conn
                .execute(
                    "INSERT INTO mailbox_readers (mailbox_id, owner, created_at, last_seen_at, key_hash)
                     VALUES (?1, ?2, ?3, ?3, ?4)
                     ON CONFLICT(mailbox_id, owner) DO UPDATE SET last_seen_at = ?3",
                    params![id, owner, now, reader_key],
                )
                .map_err(|e| e.to_string())?;
            if !exists {
                count += 1;
            }
        }
        for id in drop {
            // Only the OWNER can remove it. Not a reader: nothing changed, and the cleanup below scans the whole box.
            let left = self
                .conn
                .execute("DELETE FROM mailbox_readers WHERE mailbox_id = ?1 AND owner = ?2", params![id, owner])
                .unwrap_or(0);
            if left == 0 {
                continue;
            }
            // A departing reader must not keep items waiting. Its own ack still counts in this cleanup, and then its
            // cursor is dropped.
            let _ = self.delete_fully_acked(id);
            let _ = self
                .conn
                .execute("DELETE FROM mail_acks WHERE mailbox_id = ?1 AND owner = ?2", params![id, owner]);
        }
        tx.commit().map_err(|e| e.to_string())?;
        Ok((refused, unproven))
    }

    /// A deposit only makes sense when someone other than the depositor reads the box on an active enrollment.
    /// Otherwise the item can only expire.
    pub fn mailbox_has_other_reader(&self, mailbox_id: &str, depositor: &[u8]) -> bool {
        self.conn
            .query_row(
                "SELECT 1 FROM mailbox_readers r JOIN enrollments e ON e.enrollment_id = r.owner
                 WHERE r.mailbox_id = ?1 AND r.owner != ?2 AND e.state = 'active' LIMIT 1",
                params![mailbox_id, depositor],
                |_| Ok(true),
            )
            .optional()
            .ok()
            .flatten()
            .unwrap_or(false)
    }

    pub fn mailbox_is_registered(&self, mailbox_id: &str) -> bool {
        self.conn
            .query_row("SELECT 1 FROM mailbox_readers WHERE mailbox_id = ?1", params![mailbox_id], |_| Ok(true))
            .optional()
            .ok()
            .flatten()
            .unwrap_or(false)
    }

    /// Row count for mailbox capacity: rows that NO reader has acknowledged yet. Rows that stay until the TTL because
    /// another reader (for example a stranger that never acks) has not acknowledged them are not counted. Otherwise that
    /// reader could fill the box and block all new deliveries.
    /// ponytail: these rows still count toward the byte quota (`recount_mail_bytes`). Malicious readers can hold the
    /// disk up to the quota for the TTL.
    #[cfg(test)]
    pub fn mailbox_item_count(&self, mailbox_id: &str) -> i64 {
        self.conn
            .query_row(
                "SELECT COUNT(*) FROM mail m WHERE m.mailbox_id = ?1
                   AND NOT EXISTS (SELECT 1 FROM mail_acks a
                                   WHERE a.mailbox_id = m.mailbox_id AND a.owner != m.depositor
                                     AND a.through_seq >= m.seq)",
                params![mailbox_id],
                |r| r.get(0),
            )
            .unwrap_or(0)
    }

    /// Same as `mailbox_item_count`, for one depositor's rows only. Capacity is per depositor: one sender (who cannot
    /// read the box) filling it stops nobody else's mail. Walks `idx_mail_hash` (mailbox, depositor), not the whole box.
    pub fn depositor_item_count(&self, mailbox_id: &str, depositor: &[u8]) -> i64 {
        self.conn
            .query_row(
                // Every row still stored: one reader's ack does not delete a row while another reader has not acked it.
                "SELECT COUNT(*) FROM mail m WHERE m.mailbox_id = ?1 AND m.depositor = ?2",
                params![mailbox_id, depositor],
                |r| r.get(0),
            )
            .unwrap_or(i64::MAX)
    }

    /// If the SAME bytes from the same depositor are already in this box, no new row is opened. The existing `seq` is
    /// returned.
    ///
    /// Crash measured on a real device (2026-08-29): client-side de-duplication recognized only `Message` envelopes. A
    /// `Handshake` was re-deposited about once a second (~15 KB each). That filled the depositor's `bytes_mail` quota
    /// within hours and locked all store-and-forward traffic for that device (see `deposit_dedup_key` in the client).
    /// The client is fixed. This check is the second defence: an old or buggy client can no longer inflate the server.
    ///
    /// Dropping the repeat is safe: the recipient already de-duplicates by `message_id`, and an identical second copy
    /// carries no information.
    pub fn deposit(&self, mailbox_id: &str, sealed: &[u8], depositor: &[u8], now: i64, ttl_ms: i64) -> Result<u64, String> {
        // Matched by hash, from the index. Comparing `sealed` itself read every same-length blob of this depositor in the
        // box on each deposit.
        let hash = Sha256::digest(sealed);
        if let Ok(existing) = self.conn.query_row(
            "SELECT seq FROM mail WHERE mailbox_id = ?1 AND depositor = ?2 AND sealed_hash = ?3 LIMIT 1",
            params![mailbox_id, depositor, hash.as_slice()],
            |row| row.get::<_, i64>(0),
        ) {
            // Refresh the TTL. If the sender keeps re-sending, the recipient has not received it yet, so the copy must not
            // expire early.
            let _ = self.conn.execute(
                "UPDATE mail SET expires_at_ms = ?1 WHERE mailbox_id = ?2 AND seq = ?3",
                params![now + ttl_ms, mailbox_id, existing],
            );
            return Ok(existing as u64);
        }
        // Row and charge together. A swallowed charge would under-count the quota.
        let charge = mail_row_bytes(mailbox_id, sealed) as i64;
        let tx = self.conn.unchecked_transaction().map_err(|e| e.to_string())?;
        let seq: i64 = self
            .conn
            .query_row(
                "INSERT INTO mail_seq (mailbox_id, last)
                 VALUES (?1, COALESCE((SELECT v FROM meta WHERE k = 'mail_seq_base'), 0) + 1)
                 ON CONFLICT(mailbox_id) DO UPDATE SET last = last + 1
                 RETURNING last",
                params![mailbox_id],
                |r| r.get(0),
            )
            .map_err(|e| e.to_string())?;
        self.conn
            .execute(
                "INSERT INTO mail (seq, mailbox_id, sealed, byte_len, deposited_at_ms, expires_at_ms, depositor, sealed_hash)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![seq, mailbox_id, sealed, charge, now, now + ttl_ms, depositor, hash.as_slice()],
            )
            .map_err(|e| e.to_string())?;
        let seq = seq as u64;
        // The quota is charged to the DEPOSITOR, not the box owner. A spam sender uses up its own quota. Nobody can fill
        // a victim's box to deny it service.
        self.conn
            .execute(
                "UPDATE enrollments SET bytes_mail = bytes_mail + ?1 WHERE enrollment_id = ?2",
                params![charge, depositor],
            )
            .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(seq)
    }

    /// Fetches the items after the cursor. Stops before `max_bytes` or `max_items` is exceeded. The rest comes in the
    /// next round (`more`).
    ///
    /// `requester`: the requester's enrollment id. Envelopes the requester ITSELF deposited are NOT returned. Both sides
    /// of a ratchet box write and read it, so without this filter each side would download its own outgoing traffic. It
    /// cannot decrypt that (the send and receive chains differ), and the log fills with "cannot decrypt" errors. Bandwidth
    /// and CPU are wasted.
    pub fn fetch(&self, requester: &[u8], cursors: &[(String, u64)], max_items: u32, max_bytes: u32) -> (Vec<MailItem>, bool) {
        let mut items = Vec::new();
        let mut total = 0usize;
        let mut more = false;

        // Only a reader that REGISTERED the box can read it.
        let Ok(mut stmt) = self.conn.prepare(
            "SELECT m.seq, m.deposited_at_ms, m.sealed FROM mail m
             WHERE m.mailbox_id = ?1 AND m.seq > ?2 AND m.depositor != ?3
               AND EXISTS (SELECT 1 FROM mailbox_readers r
                           WHERE r.mailbox_id = m.mailbox_id AND r.owner = ?3)
             ORDER BY m.seq",
        ) else {
            return (items, false);
        };
        for (mailbox_id, after_seq) in cursors {
            if items.len() as u32 >= max_items || total >= max_bytes as usize {
                more = true;
                break;
            }
            let rows = stmt.query_map(params![mailbox_id, (*after_seq).min(i64::MAX as u64) as i64, requester], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, Vec<u8>>(2)?))
            });
            let Ok(rows) = rows else { continue };
            for (seq, deposited_at_ms, sealed) in rows.flatten() {
                // The first item always goes out, even over `max_bytes`. Otherwise an item larger than the batch cap blocks
                // its mailbox (zero items, `more` forever) until the TTL.
                if items.len() as u32 >= max_items || (!items.is_empty() && total + sealed.len() > max_bytes as usize) {
                    more = true;
                    break;
                }
                total += sealed.len();
                items.push(MailItem {
                    mailbox_id: mailbox_id.clone(),
                    seq: seq as u64,
                    deposited_at_ms: deposited_at_ms as u64,
                    sealed,
                });
            }
        }
        (items, more)
    }

    /// Cumulative delete.
    ///
    /// ONLY the side that DEPOSITED the envelope can delete it. Group messaging is pairwise, so a `mb_*` box has exactly
    /// two possible readers, and one of them is the depositor. There is no need for accounting of "have all subscribers
    /// acknowledged". The depositor's own `Ack` is silently ignored. Otherwise a sender could delete a message before the
    /// recipient saw it.
    /// Deletes the items in `mailbox_id` that `reader` has not acknowledged (and did not deposit itself). See
    /// `ServerRequest::Push`.
    pub fn unacked_for(&self, mailbox_id: &str, reader: &[u8]) -> i64 {
        self.conn
            .query_row(
                "SELECT COUNT(*) FROM mail m WHERE m.mailbox_id = ?1 AND m.depositor != ?2
                   AND m.seq > COALESCE((SELECT a.through_seq FROM mail_acks a
                                         WHERE a.mailbox_id = ?1 AND a.owner = ?2), 0)",
                params![mailbox_id, reader],
                |r| r.get(0),
            )
            .unwrap_or(i64::MAX)
    }

    pub fn ack(&self, mailbox_id: &str, through_seq: u64, acker: &[u8]) -> Result<usize, String> {
        // Only a reader that REGISTERED the box can acknowledge.
        let is_reader = self
            .conn
            .query_row(
                "SELECT 1 FROM mailbox_readers WHERE mailbox_id = ?1 AND owner = ?2",
                params![mailbox_id, acker],
                |_| Ok(true),
            )
            .optional()
            .map_err(|e| e.to_string())?
            .unwrap_or(false);
        if !is_reader {
            return Ok(0);
        }
        // Clamped to what the box holds. An ack of a future seq would otherwise cover every later item too.
        let moved = self
            .conn
            .execute(
                "INSERT INTO mail_acks (mailbox_id, owner, through_seq)
                 VALUES (?1, ?2, MIN(?3, COALESCE((SELECT MAX(seq) FROM mail WHERE mailbox_id = ?1), 0)))
                 ON CONFLICT(mailbox_id, owner) DO UPDATE SET through_seq = excluded.through_seq
                 WHERE excluded.through_seq > mail_acks.through_seq",
                params![mailbox_id, acker, through_seq.min(i64::MAX as u64) as i64],
            )
            .map_err(|e| e.to_string())?;
        // The cursor did not move: nothing new to delete. The delete scans the whole box, and a repeated ack ran it 512
        // times per request.
        if moved == 0 {
            return Ok(0);
        }
        self.delete_fully_acked(mailbox_id)
    }

    /// Deletes the rows that every registered reader OTHER than the depositor has acknowledged (and at least one of them
    /// really has). A reader that has not acknowledged (for example a stranger registered to the box) keeps the row until
    /// the TTL, but cannot delete someone else's mail.
    fn delete_fully_acked(&self, mailbox_id: &str) -> Result<usize, String> {
        self.conn
            .execute(
                "DELETE FROM mail WHERE mailbox_id = ?1
                   AND EXISTS (SELECT 1 FROM mail_acks a
                               WHERE a.mailbox_id = mail.mailbox_id AND a.owner != mail.depositor
                                 AND a.through_seq >= mail.seq)
                   AND NOT EXISTS (SELECT 1 FROM mailbox_readers r
                                   WHERE r.mailbox_id = mail.mailbox_id AND r.owner != mail.depositor
                                     AND EXISTS (SELECT 1 FROM enrollments e
                                                 WHERE e.enrollment_id = r.owner AND e.state = 'active')
                                     AND COALESCE((SELECT a.through_seq FROM mail_acks a
                                                   WHERE a.mailbox_id = r.mailbox_id AND a.owner = r.owner), 0) < mail.seq)",
                params![mailbox_id],
            )
            .map_err(|e| e.to_string())
    }

    /// Deletes expired delivery items. A safety net on top of acks: a recipient that never comes back must not let the box
    /// grow forever. See `ServerRequest::Cancel`: the sender withdraws its OWN undelivered packet. The `depositor = ?3`
    /// condition is critical: you can delete only what you deposited, never someone else's.
    pub fn cancel_own_deposits(&self, mailbox_id: &str, seqs: &[u64], depositor: &[u8]) -> usize {
        let mut removed = 0usize;
        for seq in seqs {
            removed += self
                .conn
                .execute(
                    "DELETE FROM mail WHERE mailbox_id = ?1 AND seq = ?2 AND depositor = ?3",
                    params![mailbox_id, (*seq).min(i64::MAX as u64) as i64, depositor],
                )
                .unwrap_or(0);
        }
        removed
    }

    /// Puts an enroll key on the block list: no new enrollment with it. See `revoke_enrollment`, which does the same for
    /// the enrollment's key.
    pub fn block_enrollment_key(&self, enroll_pk: &[u8], now: i64) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO blocked_keys (enroll_pk, blocked_at) VALUES (?1, ?2)",
                params![enroll_pk, now],
            )
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    pub fn unblock_enrollment_key(&self, enroll_pk: &[u8]) {
        let _ = self
            .conn
            .execute("DELETE FROM blocked_keys WHERE enroll_pk = ?1", params![enroll_pk]);
    }

    pub fn is_key_blocked(&self, enroll_pk: &[u8]) -> bool {
        self.conn
            .query_row("SELECT 1 FROM blocked_keys WHERE enroll_pk = ?1", params![enroll_pk], |_| Ok(true))
            .optional()
            .ok()
            .flatten()
            .unwrap_or(false)
    }

    pub fn sweep_expired_mail(&self, now: i64) -> usize {
        // Reader rows of owners whose enrollment was deleted or revoked can no longer acknowledge. `delete_fully_acked` no
        // longer counts them. Re-evaluate the boxes so that waiting mail is released.
        let mut orphaned: Vec<String> = Vec::new();
        if let Ok(mut st) = self.conn.prepare(
            "SELECT DISTINCT mailbox_id FROM mailbox_readers
             WHERE owner NOT IN (SELECT enrollment_id FROM enrollments WHERE state = 'active')",
        ) {
            if let Ok(rows) = st.query_map([], |r| r.get::<_, String>(0)) {
                orphaned.extend(rows.flatten());
            }
        }
        let _ = self.conn.execute(
            "DELETE FROM mailbox_readers WHERE owner NOT IN (SELECT enrollment_id FROM enrollments WHERE state = 'active')",
            [],
        );
        // Counted in the result, so the caller recounts the depositors' quota.
        let mut removed = 0;
        for mailbox in &orphaned {
            removed += self.delete_fully_acked(mailbox).unwrap_or(0);
        }
        let _ = self.conn.execute(
            "DELETE FROM mail_acks WHERE NOT EXISTS (SELECT 1 FROM mailbox_readers r
                WHERE r.mailbox_id = mail_acks.mailbox_id AND r.owner = mail_acks.owner)",
            [],
        );
        removed
            + self
                .conn
                .execute("DELETE FROM mail WHERE expires_at_ms <= ?1", params![now])
                .unwrap_or(0)
    }

    /// Deletes archive rows not written for `ARCHIVE_TTL_MS`. Quotas are recounted.
    pub fn sweep_expired_archive(&self, now: i64) -> usize {
        let cutoff = now - ARCHIVE_TTL_MS;
        let mut owners: Vec<Vec<u8>> = Vec::new();
        if let Ok(mut st) = self.conn.prepare("SELECT DISTINCT owner FROM archive WHERE updated_at < ?1") {
            if let Ok(rows) = st.query_map(params![cutoff], |r| r.get::<_, Vec<u8>>(0)) {
                owners.extend(rows.flatten());
            }
        }
        let n = self.conn.execute("DELETE FROM archive WHERE updated_at < ?1", params![cutoff]).unwrap_or(0);
        if n > 0 {
            self.recount_archive_bytes(&owners);
        }
        n
    }

    // -----------------------------------------------------------------
    // Archive
    // -----------------------------------------------------------------

    /// Stores or overwrites records.
    ///
    /// `WHERE excluded.rev > archive.rev`: an edit or delete carries the SAME `record_id` and overwrites the old row with a
    /// higher `rev`. The existing `HistorySyncResponse` cannot do this (it cannot correct a late Edit in history). The same
    /// rule also collapses N devices uploading the same record into one row.
    ///
    /// The last writer becomes `owner` and pays for the row (see `archive_row_bytes`).
    pub fn archive_put(&self, bucket: &str, records: &[ArchiveRecord], owner: &[u8], now: i64) -> Result<u64, String> {
        let mut newest = 0u64;
        // One transaction: one WAL commit per batch, all or nothing. The charge moves by the delta of each row written, in
        // the same transaction. A `SUM` over all of the writer's rows on every request was a full scan on the event loop.
        // The sweep recounts.
        let tx = self.conn.unchecked_transaction().map_err(|e| e.to_string())?;
        for rec in records {
            // Skipped, not refused: the client drops what was answered `Ok`. One over-long id must not block its archive
            // queue.
            if rec.record_id.len() > 128 {
                continue;
            }
            let old = self.conn.query_row(
                "SELECT owner, byte_len FROM archive WHERE bucket = ?1 AND record_id = ?2",
                params![bucket, rec.record_id],
                |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, i64>(1)?)),
            ).ok();
            let bytes = archive_row_bytes(rec) as i64;
            let written = self.conn
                .execute(
                    "INSERT INTO archive (bucket, record_id, rev, sent_at_ms, sealed, byte_len, owner, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                     ON CONFLICT(bucket, record_id) DO UPDATE SET
                        rev = excluded.rev, sent_at_ms = excluded.sent_at_ms,
                        sealed = excluded.sealed, byte_len = excluded.byte_len,
                        owner = excluded.owner, updated_at = excluded.updated_at
                     WHERE excluded.rev > archive.rev",
                    params![bucket, rec.record_id, rec.rev.min(i64::MAX as u64) as i64, rec.sent_at_ms.min(i64::MAX as u64) as i64, rec.sealed, bytes, owner, now],
                )
                .map_err(|e| e.to_string())?;
            if written > 0 {
                if let Some((old_owner, old_bytes)) = &old {
                    self.conn
                        .execute(
                            "UPDATE enrollments SET bytes_archive = MAX(0, bytes_archive - ?1) WHERE enrollment_id = ?2",
                            params![old_bytes, old_owner],
                        )
                        .map_err(|e| e.to_string())?;
                }
                self.conn
                    .execute(
                        "UPDATE enrollments SET bytes_archive = bytes_archive + ?1 WHERE enrollment_id = ?2",
                        params![bytes, owner],
                    )
                    .map_err(|e| e.to_string())?;
            }
            newest = newest.max(rec.rev);
        }
        tx.commit().map_err(|e| e.to_string())?;
        Ok(newest)
    }

    /// Only the owners whose rows changed are recounted (an overwrite or purge changes what another enrollment is charged).
    /// Recounting every enrollment scanned the whole archive on each request.
    fn recount_archive_bytes(&self, owners: &[Vec<u8>]) {
        for owner in owners {
            let _ = self.conn.execute(
                "UPDATE enrollments SET bytes_archive =
                    COALESCE((SELECT SUM(byte_len) FROM archive WHERE archive.owner = ?1), 0)
                 WHERE enrollment_id = ?1",
                params![owner],
            );
        }
    }

    pub fn archive_probe(&self, buckets: &[String]) -> Vec<BucketStat> {
        let mut out = Vec::new();
        // A repeated id is one scan, and the count stops at a cap. 512 full scans of a bucket of millions of rows held the
        // event loop for seconds. MIN and MAX come from `idx_archive_page`.
        let mut seen = std::collections::HashSet::new();
        for b in buckets {
            if !seen.insert(b.as_str()) {
                continue;
            }
            let row = self.conn.query_row(
                "SELECT (SELECT COUNT(*) FROM (SELECT 1 FROM archive WHERE bucket = ?1 LIMIT 65536)),
                        COALESCE((SELECT MIN(sent_at_ms) FROM archive WHERE bucket = ?1), 0),
                        COALESCE((SELECT MAX(sent_at_ms) FROM archive WHERE bucket = ?1), 0)",
                params![b],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?)),
            );
            if let Ok((count, oldest, newest)) = row {
                if count > 0 {
                    out.push(BucketStat {
                        bucket: b.clone(),
                        count: count as u32,
                        oldest_ms: oldest as u64,
                        newest_ms: newest as u64,
                    });
                }
            }
        }
        out
    }

    /// Pages backwards, newest first. `before: None` returns the newest page.
    ///
    /// The cursor is the last record the client received, `(sent_at_ms, record_id)`. Clients send `sent_at_ms` rounded to
    /// the hour, so many records share one value, and a page can end inside such a group.
    pub fn archive_fetch(&self, bucket: &str, before: Option<(u64, &str)>, max_items: u32, max_bytes: u32) -> (Vec<ArchiveRecord>, bool) {
        let (before_ms, before_id) = match before {
            Some((ms, id)) => (ms.min(i64::MAX as u64) as i64, id),
            None => (i64::MAX, ""),
        };
        let mut stmt = match self.conn.prepare(
            "SELECT record_id, rev, sent_at_ms, sealed FROM archive
             WHERE bucket = ?1 AND (sent_at_ms < ?2 OR (sent_at_ms = ?2 AND record_id < ?3))
             ORDER BY sent_at_ms DESC, record_id DESC",
        ) {
            Ok(s) => s,
            Err(_) => return (Vec::new(), false),
        };
        let rows = stmt.query_map(params![bucket, before_ms, before_id], |r| {
            Ok(ArchiveRecord {
                record_id: r.get(0)?,
                rev: r.get::<_, i64>(1)? as u64,
                sent_at_ms: r.get::<_, i64>(2)? as u64,
                sealed: r.get(3)?,
            })
        });
        let Ok(rows) = rows else { return (Vec::new(), false) };

        let mut out: Vec<ArchiveRecord> = Vec::new();
        let mut total = 0usize;
        for rec in rows.flatten() {
            // `!out.is_empty()`: the first record always goes out. Otherwise one record over `max_bytes` would hide
            // everything older in its bucket.
            if !out.is_empty() && (out.len() as u32 >= max_items || total + rec.sealed.len() > max_bytes as usize) {
                return (out, true);
            }
            total += rec.sealed.len();
            out.push(rec);
        }
        (out, false)
    }

    /// Deletes whole buckets, whoever uploaded the rows. The bucket id is the capability, as it is for `archive_fetch` and
    /// for overwriting a record. A chat deleted on one linked device is deleted for all of them.
    pub fn archive_purge(&self, buckets: &[String]) -> usize {
        let mut n = 0;
        let mut owners: Vec<Vec<u8>> = Vec::new();
        for b in buckets {
            if let Ok(mut st) = self.conn.prepare("SELECT DISTINCT owner FROM archive WHERE bucket = ?1") {
                if let Ok(rows) = st.query_map(params![b], |r| r.get::<_, Vec<u8>>(0)) {
                    for o in rows.flatten() {
                        if !owners.contains(&o) {
                            owners.push(o);
                        }
                    }
                }
            }
            n += self.conn.execute("DELETE FROM archive WHERE bucket = ?1", params![b]).unwrap_or(0);
        }
        self.recount_archive_bytes(&owners);
        n
    }

    // -----------------------------------------------------------------
    // Blob (file attachment)
    // -----------------------------------------------------------------

    pub fn blob_begin(&self, blob_id: &str, owner: &[u8], total_chunks: u32, now: i64) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT INTO blobs (blob_id, owner, total_chunks, received_chunks, byte_len, complete, created_at, last_served_at)
                 VALUES (?1, ?2, ?3, 0, 0, 0, ?4, ?4)
                 ON CONFLICT(blob_id) DO NOTHING",
                params![blob_id, owner, total_chunks as i64, now],
            )
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// Has this chunk arrived before? (Retransmission is possible in the pipeline.)
    pub fn blob_has_chunk(&self, blob_id: &str, chunk_index: u32) -> bool {
        self.conn
            .query_row(
                "SELECT 1 FROM blob_chunks WHERE blob_id = ?1 AND chunk_index = ?2",
                params![blob_id, chunk_index as i64],
                |_| Ok(true),
            )
            .optional()
            .ok()
            .flatten()
            .unwrap_or(false)
    }

    pub fn blob_record_chunk(&self, blob_id: &str, chunk_index: u32, len: usize) -> Result<(), String> {
        // `received_chunks` is a COUNT of distinct chunks, not a high-water mark. Chunks may arrive out of order (the
        // pipeline can have several `BlobPut`s in flight), and a re-sent chunk must not advance the count.
        // Chunk recording is idempotent: if the same index arrives again (connection dropped, client re-sent), neither the
        // count nor the bytes go up twice.
        let inserted = self
            .conn
            .execute(
                "INSERT OR IGNORE INTO blob_chunks (blob_id, chunk_index, byte_len) VALUES (?1, ?2, ?3)",
                params![blob_id, chunk_index as i64, len as i64],
            )
            .map_err(|e| e.to_string())?;
        if inserted == 0 {
            return Ok(());
        }
        // `received_chunks` is now a real count, not a high-water mark, because chunks can arrive out of order.
        self.conn
            .execute(
                "UPDATE blobs SET byte_len = byte_len + ?2,
                                  received_chunks = (SELECT COUNT(*) FROM blob_chunks WHERE blob_id = ?1)
                 WHERE blob_id = ?1",
                params![blob_id, len as i64],
            )
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// Returns `Err` also when no row matched (gone, or chunks missing). The caller must not answer `Ok` for a blob that
    /// will never be served.
    pub fn blob_finish(&self, blob_id: &str, enc_sha256: &[u8], now: i64) -> Result<(), String> {
        let n = self
            .conn
            .execute(
                "UPDATE blobs SET complete = 1, enc_sha256 = ?2, last_served_at = ?3
                 WHERE blob_id = ?1 AND received_chunks >= total_chunks",
                params![blob_id, enc_sha256, now],
            )
            .map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("Blob tamamlanamadı (eksik parça ya da satır yok)".to_string());
        }
        Ok(())
    }

    pub fn blob_state(&self, blob_id: &str) -> Option<BlobState> {
        self.conn
            .query_row(
                "SELECT blob_id, owner, total_chunks, received_chunks, byte_len, complete, chunk_size FROM blobs WHERE blob_id = ?1",
                params![blob_id],
                |r| {
                    Ok(BlobState {
                        blob_id: r.get(0)?,
                        owner: r.get(1)?,
                        total_chunks: r.get::<_, i64>(2)? as u32,
                        received_chunks: r.get::<_, i64>(3)? as u32,
                        byte_len: r.get(4)?,
                        complete: r.get::<_, i64>(5)? != 0,
                        chunk_size: r.get::<_, i64>(6)?.max(0) as u32,
                    })
                },
            )
            .optional()
            .ok()
            .flatten()
    }

    pub fn blob_touch(&self, blob_id: &str, now: i64) {
        let _ = self.conn.execute("UPDATE blobs SET last_served_at = ?2 WHERE blob_id = ?1", params![blob_id, now]);
    }

    /// `true` if `owner` owned the blob. The caller then removes the file.
    pub fn blob_delete(&self, blob_id: &str, owner: &[u8]) -> bool {
        let owned = self.blob_state(blob_id).map_or(false, |s| s.owner == owner);
        if owned {
            self.blob_forget(blob_id);
        }
        owned
    }

    /// Returns the blob ids to delete. The caller removes the files.
    ///
    /// Two rules. Completed blobs live for `blob_ttl_ms` after their LAST SERVE, so a file still being downloaded keeps
    /// living. Unfinished uploads are dropped 24 hours after their last chunk (`blob_touch` per chunk).
    pub fn blobs_to_gc(&self, now: i64, ttl_ms: i64) -> Vec<String> {
        let mut stmt = match self.conn.prepare(
            "SELECT blob_id FROM blobs
             WHERE (complete = 1 AND last_served_at + ?1 <= ?2)
                OR (complete = 0 AND last_served_at + 86400000 <= ?2)
             LIMIT 512",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        stmt.query_map(params![ttl_ms, now], |r| r.get::<_, String>(0))
            .map(|it| it.filter_map(|r| r.ok()).collect())
            .unwrap_or_default()
    }

    /// The one way a blob leaves the DB. It refunds the owner exactly the bytes charged (`byte_len`, not the file length:
    /// a sparse file is far longer than what was paid for), and drops the chunk rows with the blob row.
    pub fn blob_forget(&self, blob_id: &str) {
        let _ = self.conn.execute(
            "UPDATE enrollments SET bytes_blob = MAX(0, bytes_blob - (SELECT byte_len FROM blobs WHERE blob_id = ?1))
             WHERE enrollment_id = (SELECT owner FROM blobs WHERE blob_id = ?1)",
            params![blob_id],
        );
        let _ = self.conn.execute("DELETE FROM blobs WHERE blob_id = ?1", params![blob_id]);
        let _ = self.conn.execute("DELETE FROM blob_chunks WHERE blob_id = ?1", params![blob_id]);
    }

    /// Blob rows (files on disk) that `owner` holds.
    pub fn blob_count(&self, owner: &[u8]) -> i64 {
        self.conn
            .query_row("SELECT COUNT(*) FROM blobs WHERE owner = ?1", params![owner], |r| r.get(0))
            .unwrap_or(i64::MAX)
    }

    // -----------------------------------------------------------------
    // Quota
    // -----------------------------------------------------------------

    /// Blob charge = what the rows record. Undoes a charge whose chunk row failed to write (see `handle_blob_put`).
    pub fn recount_blob_bytes(&self) {
        let _ = self.conn.execute_batch(
            "UPDATE enrollments SET bytes_blob =
                COALESCE((SELECT SUM(byte_len) FROM blobs WHERE blobs.owner = enrollments.enrollment_id), 0);",
        );
    }

    pub fn add_blob_bytes(&self, owner: &[u8], delta: i64) {
        let _ = self.conn.execute(
            "UPDATE enrollments SET bytes_blob = MAX(0, bytes_blob + ?1) WHERE enrollment_id = ?2",
            params![delta, owner],
        );
    }

    /// Subtracts the bytes of deleted delivery items from their depositors' quotas. Called after `ack` and
    /// `sweep_expired_mail`. Otherwise the quota only grows, and an active user would get locked out of the server within
    /// a few months.
    pub fn recount_mail_bytes(&self) {
        let _ = self.conn.execute_batch(
            "UPDATE enrollments SET bytes_mail =
                COALESCE((SELECT SUM(byte_len) FROM mail WHERE mail.depositor = enrollments.enrollment_id), 0);",
        );
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
mod tests {
    use super::*;

    fn rec(id: &str, rev: u64, ts: u64, body: &[u8]) -> ArchiveRecord {
        ArchiveRecord { record_id: id.to_string(), rev, sent_at_ms: ts, sealed: body.to_vec() }
    }

    /// Reading a mailbox requires a REGISTERED reader (see `mailbox_readers`). In the real flow `Register` always
    /// comes before `Fetch`. The tests used to skip that step.
    fn register(store: &Store, owner: &[u8], mailbox: &str) {
        store
            .register_mailboxes(owner, &[mailbox.to_string()], &[], 0, 100)
            .unwrap();
    }

    fn enroll(store: &Store, id: &[u8], peer: &str) -> Vec<u8> {
        let e = Enrollment {
            enrollment_id: id.to_vec(),
            enroll_pk: vec![1; 32],
            enroll_pk_pq: vec![2; 32],
            peer_id: peer.to_string(),
            state: EnrollmentState::Active,
            enrolled_at: 0,
            last_seen_at: 0,
            bytes_mail: 0,
            bytes_archive: 0,
            bytes_blob: 0,
        };
        store.insert_enrollment(&e).unwrap();
        id.to_vec()
    }

    /// Revoke is a block: the key is refused until the operator lifts the block. The revoked row stays, so the
    /// PeerId still leads to the blocked key.
    #[test]
    fn a_revoked_device_is_blocked_until_unblocked() {
        let s = Store::open_in_memory().unwrap();
        let id = enroll(&s, b"oldoldoldoldold1", "peerR");
        assert!(!s.is_key_blocked(&[1u8; 32]));
        s.revoke_enrollment(&id).unwrap();
        let revoked = s.enrollment_by_peer("peerR").unwrap();
        assert_eq!(revoked.state, EnrollmentState::Revoked);
        assert!(s.is_key_blocked(&revoked.enroll_pk));
        // The idle sweep must not remove the row that carries the block.
        s.sleep_idle_enrollments(i64::MAX);
        assert!(s.enrollment_by_peer("peerR").is_some());
        s.unblock_enrollment_key(&revoked.enroll_pk);
        assert!(!s.is_key_blocked(&revoked.enroll_pk));
    }

    /// Operator decision: an idle enrollment goes to sleep, it is not removed.
    #[test]
    fn an_idle_enrollment_sleeps_and_rebinds_without_an_invite() {
        let s = Store::open_in_memory().unwrap();
        let a = enroll(&s, b"aaaa", "peerA");
        let b = enroll(&s, b"bbbb", "peerB");
        register(&s, &a, "box");
        register(&s, &a, "shared");
        register(&s, &b, "shared");
        s.deposit("box", b"waiting", &b, 1, 1000).unwrap();
        s.deposit("shared", b"kept", &a, 2, 1000).unwrap();
        s.deposit("shared", b"own", &b, 3, 1000).unwrap();
        s.conn.execute("UPDATE enrollments SET bytes_archive = 7 WHERE enrollment_id = ?1", params![a]).unwrap();
        s.touch_enrollment(&b, 1_000);
        assert_eq!(s.count_active_enrollments(500), 1);
        assert_eq!(s.sleep_idle_enrollments(500), 2, "mail only a sleeper or its depositor reads goes");
        let row = s.enrollment_by_id(&a).expect("the row stays");
        assert_eq!(row.state, EnrollmentState::Active);
        assert_eq!(row.bytes_archive, 7, "quota counters stay");
        assert!(!s.mailbox_is_registered("box"));
        assert!(s.mailbox_is_registered("shared"), "b still reads it");
        assert_eq!(s.count_active_enrollments(500), 1, "a sleeper holds no place under the cap");
        s.rebind_enrollment(&a, "peerA2", 2_000).unwrap();
        assert_eq!(s.enrollment_by_peer("peerA2").unwrap().enrollment_id, a);
        assert_eq!(s.count_active_enrollments(500), 2, "back awake");
    }

    #[test]
    fn mail_seq_counts_per_mailbox_and_never_resets() {
        let s = Store::open_in_memory().unwrap();
        assert_eq!(s.deposit("mb_1", b"x", b"e", 1, 1000).unwrap(), 1);
        assert_eq!(s.deposit("mb_2", b"y", b"e", 1, 1000).unwrap(), 1, "another box does not move this one");
        assert_eq!(s.deposit("mb_1", b"z", b"e", 1, 1000).unwrap(), 2);
        s.conn.execute("DELETE FROM mail", []).unwrap();
        assert_eq!(s.deposit("mb_1", b"w", b"e", 1, 1000).unwrap(), 3, "an emptied box keeps counting");
    }

    #[test]
    fn old_global_mail_seq_migrates_above_old_cursors() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE mail (seq INTEGER PRIMARY KEY AUTOINCREMENT, mailbox_id TEXT NOT NULL, sealed BLOB NOT NULL,
                 byte_len INTEGER NOT NULL, deposited_at_ms INTEGER NOT NULL, expires_at_ms INTEGER NOT NULL, depositor BLOB NOT NULL);
             INSERT INTO mail VALUES (41, 'mb_1', x'00', 1, 1, 9999, x'01');",
        )
        .unwrap();
        let s = Store { conn };
        s.init_schema().unwrap();
        assert_eq!(s.deposit("mb_2", b"y", b"e", 1, 1000).unwrap(), 42);
        assert_eq!(s.deposit("mb_1", b"y", b"e", 1, 1000).unwrap(), 42);
        assert_eq!(s.depositor_item_count("mb_1", b"\x01"), 1, "the old row survives");
    }

    #[test]
    fn deposit_fetch_cursor_never_repeats_or_skips() {
        let s = Store::open_in_memory().unwrap();
        let a = enroll(&s, b"aaaa", "peerA");
        s.register_mailboxes(&a, &["mb_1".into()], &[], 0, 10).unwrap();

        let s1 = s.deposit("mb_1", b"one", &a, 1, 1000).unwrap();
        let s2 = s.deposit("mb_1", b"two", &a, 2, 1000).unwrap();
        assert!(s2 > s1, "seq kesin artan olmali");

        let b = enroll(&s, b"bbbb", "peerB");
        register(&s, &b, "mb_1");
        let (items, _) = s.fetch(&b, &[("mb_1".into(), 0)], 10, 4096);
        assert_eq!(items.len(), 2);
        // Advance the cursor. The same items must not arrive again.
        let (again, _) = s.fetch(&b, &[("mb_1".into(), s2)], 10, 4096);
        assert!(again.is_empty(), "islenmis ogeler tekrar gelmemeli");
        // Continue from the middle. No gap must appear.
        let (mid, _) = s.fetch(&b, &[("mb_1".into(), s1)], 10, 4096);
        assert_eq!(mid.len(), 1);
        assert_eq!(mid[0].sealed, b"two");
    }

    #[test]
    fn unacked_counts_only_what_the_reader_has_not_acked() {
        let s = Store::open_in_memory().unwrap();
        let a = enroll(&s, b"aaaa", "peerA");
        let b = enroll(&s, b"bbbb", "peerB");
        s.register_mailboxes(&a, &["mb_1".into()], &[], 0, 10).unwrap();
        s.register_mailboxes(&b, &["mb_1".into()], &[], 0, 10).unwrap();
        let s1 = s.deposit("mb_1", b"one", &a, 1, 1000).unwrap();
        assert_eq!(s.unacked_for("mb_1", &b), 1, "only the new item: safe to push inline");
        assert_eq!(s.unacked_for("mb_1", &a), 0, "own deposits never count");
        s.deposit("mb_1", b"two", &a, 2, 1000).unwrap();
        assert_eq!(s.unacked_for("mb_1", &b), 2, "an older item is pending: Notify only");
        s.ack("mb_1", s1, &b).unwrap();
        assert_eq!(s.unacked_for("mb_1", &b), 1);
    }

    #[test]
    fn fetch_respects_byte_and_item_caps() {
        let s = Store::open_in_memory().unwrap();
        let a = enroll(&s, b"aaaa", "peerA");
        for i in 0..10 {
            // The bytes differ per deposit: `deposit` now de-duplicates identical copies (see there), and in practice
            // two separate envelopes never have the same ciphertext.
            let mut body = vec![b'x'; 100];
            body[0] = i as u8;
            s.deposit("mb_1", &body, &a, i, 1000).unwrap();
        }
        let b = enroll(&s, b"bbbb", "peerB");
        register(&s, &b, "mb_1");
        let (items, more) = s.fetch(&b, &[("mb_1".into(), 0)], 3, 4096);
        assert_eq!(items.len(), 3);
        assert!(more);
        let (items, more) = s.fetch(&b, &[("mb_1".into(), 0)], 100, 250);
        assert!(items.len() <= 2 && more, "bayt tavani uygulanmali");
    }

    #[test]
    fn fetch_does_not_return_the_requesters_own_deposits() {
        // Both sides of a ratchet box write to it and read from it. Without a filter, each side downloads its own
        // outgoing traffic and cannot decrypt it.
        let s = Store::open_in_memory().unwrap();
        let a = enroll(&s, b"aaaa", "peerA");
        let b = enroll(&s, b"bbbb", "peerB");
        // Both sides of a ratchet box register it. See `mailbox_readers`.
        register(&s, &a, "mb_1");
        register(&s, &b, "mb_1");
        s.deposit("mb_1", b"a-dan", &a, 1, 1000).unwrap();
        s.deposit("mb_1", b"b-den", &b, 2, 1000).unwrap();

        let (for_a, _) = s.fetch(&a, &[("mb_1".into(), 0)], 10, 4096);
        assert_eq!(for_a.len(), 1);
        assert_eq!(for_a[0].sealed, b"b-den", "A sadece B'nin biraktigini gormeli");

        let (for_b, _) = s.fetch(&b, &[("mb_1".into(), 0)], 10, 4096);
        assert_eq!(for_b.len(), 1);
        assert_eq!(for_b[0].sealed, b"a-dan");
    }

    #[test]
    fn a_new_reader_needs_a_proof() {
        // A session box: its id is derived from the one key both ends derive.
        let s = Store::open_in_memory().unwrap();
        let owner = enroll(&s, b"aaaa", "peerA");
        let peer = enroll(&s, b"bbbb", "peerB");
        let squatter = enroll(&s, b"cccc", "peerC");
        let key = [1u8; 32].to_vec();
        let mb = server_proto::key_bound_mailbox_id(&key);
        let id = vec![mb.clone()];
        let proof = |key: &[u8]| vec![(mb.clone(), key.to_vec())];
        // No proof: not registered, reported as unproven.
        assert_eq!(s.register_mailboxes_proved(&owner, &id, &[], &[], 0, 10).unwrap(), (vec![], id.clone()));
        assert!(!s.mailbox_is_registered(&mb));
        assert_eq!(s.register_mailboxes_proved(&owner, &id, &[], &proof(&key), 0, 10).unwrap(), (vec![], vec![]));
        // The same key is taken (second end of a session).
        assert_eq!(s.register_mailboxes_proved(&peer, &id, &[], &proof(&key), 0, 10).unwrap(), (vec![], vec![]));
        // Whoever knows only the id proves it with a key of its own: refused.
        assert_eq!(s.register_mailboxes_proved(&squatter, &id, &[], &proof(&[2u8; 32]), 0, 10).unwrap(), (id.clone(), vec![]));
        let rows = s.conn.query_row("SELECT COUNT(*) FROM mailbox_readers WHERE owner = ?1", params![&squatter], |r| r.get::<_, i64>(0)).unwrap();
        assert_eq!(rows, 0);
        // A reader registers again without a proof.
        assert_eq!(s.register_mailboxes_proved(&owner, &id, &[], &[], 1, 10).unwrap(), (vec![], vec![]));
    }

    #[test]
    fn a_squatter_key_neither_locks_out_nor_deletes_for_the_real_reader() {
        // A co-member knows a first-contact id (not key-bound) and proves it with a key of its own, on two
        // enrollments, before the device does.
        let s = Store::open_in_memory().unwrap();
        let sq1 = enroll(&s, b"aaaa", "peerA");
        let sq2 = enroll(&s, b"bbbb", "peerB");
        let device = enroll(&s, b"cccc", "peerC");
        let sender = enroll(&s, b"dddd", "peerD");
        let id = vec!["mb_1".to_string()];
        let proof = |key: &[u8]| vec![("mb_1".to_string(), key.to_vec())];
        for sq in [&sq1, &sq2] {
            assert_eq!(s.register_mailboxes_proved(sq, &id, &[], &proof(b"squat"), 0, 10).unwrap(), (vec![], vec![]));
        }
        assert_eq!(s.register_mailboxes_proved(&device, &id, &[], &proof(b"device"), 1, 10).unwrap(), (vec![], vec![]));
        let seq = s.deposit("mb_1", b"to-device", &sender, 2, 1000).unwrap();
        s.ack("mb_1", seq, &sq1).unwrap();
        s.ack("mb_1", seq, &sq2).unwrap();
        let (got, _) = s.fetch(&device, &[("mb_1".into(), 0)], 10, 4096);
        assert_eq!(got.len(), 1, "the squatters' acks do not delete the device's copy");
        s.ack("mb_1", seq, &device).unwrap();
        assert!(s.fetch(&device, &[("mb_1".into(), 0)], 10, 4096).0.is_empty());
    }

    #[test]
    fn a_key_takes_no_third_reader() {
        let s = Store::open_in_memory().unwrap();
        let a = enroll(&s, b"aaaa", "peerA");
        let b = enroll(&s, b"bbbb", "peerB");
        let c = enroll(&s, b"cccc", "peerC");
        let d = enroll(&s, b"eeee", "peerE");
        register(&s, &a, "mb_1");
        register(&s, &b, "mb_1");
        register(&s, &a, "mb_1");
        let id = vec!["mb_1".to_string()];
        // Another key takes its own slots, not the slots of "test-key".
        let other = vec![("mb_1".to_string(), b"other-key".to_vec())];
        assert!(s.register_mailboxes_proved(&d, &id, &[], &other, 0, 100).unwrap().0.is_empty());
        // The same key from a new enrollment (restored device) takes the place of the reader seen longest ago, once
        // that one has been idle long enough.
        let week = READER_EVICT_IDLE_MS;
        s.register_mailboxes(&b, &id, &[], week, 100).unwrap();
        assert_eq!(s.register_mailboxes(&c, &id, &[], week - 1, 100).unwrap(), id, "a, seen at 0, is not idle yet");
        // Its own requests keep a reader alive, not only its Register.
        s.touch_enrollment(&a, 10);
        assert_eq!(s.register_mailboxes(&c, &id, &[], week + 5, 100).unwrap(), id, "a was seen at 10");
        assert!(s.register_mailboxes(&c, &id, &[], week + 10, 100).unwrap().is_empty());
        assert!(s.mailbox_has_other_reader("mb_1", &a), "b and c read it");
        let aa = s.conn.query_row("SELECT COUNT(*) FROM mailbox_readers WHERE owner = ?1", params![&a], |r| r.get::<_, i64>(0)).unwrap();
        assert_eq!(aa, 0, "a was the stalest reader");
    }

    #[test]
    fn depositor_cannot_delete_its_own_message() {
        // Otherwise a sender could delete a message before the recipient saw it.
        let s = Store::open_in_memory().unwrap();
        let sender = enroll(&s, b"send", "peerS");
        let recipient = enroll(&s, b"recv", "peerR");
        register(&s, &recipient, "mb_1");
        let seq = s.deposit("mb_1", b"hello", &sender, 1, 1000).unwrap();

        assert_eq!(s.ack("mb_1", seq, &sender).unwrap(), 0, "birakan silememeli");
        assert_eq!(s.mailbox_item_count("mb_1"), 1);
        assert_eq!(s.ack("mb_1", seq, &recipient).unwrap(), 1, "alici silebilmeli");
        assert_eq!(s.mailbox_item_count("mb_1"), 0);
    }

    #[test]
    fn ack_is_cumulative_and_idempotent() {
        let s = Store::open_in_memory().unwrap();
        let sender = enroll(&s, b"send", "peerS");
        let recipient = enroll(&s, b"recv", "peerR");
        register(&s, &recipient, "mb_1");
        let mut last = 0;
        for i in 0..5 {
            // See `fetch_respects_byte_and_item_caps`: the same note applies. Deposits de-duplicate identical bytes,
            // so each round uses different bytes.
            last = s.deposit("mb_1", &[b'x', i as u8], &sender, i, 1000).unwrap();
        }
        assert_eq!(s.ack("mb_1", last, &recipient).unwrap(), 5);
        // A repeated ack is not an error, just zero rows.
        assert_eq!(s.ack("mb_1", last, &recipient).unwrap(), 0);
    }

    /// See `Store::deposit`. Because of a gap in client-side de-duplication, the same handshake was re-deposited about
    /// once a second and filled the depositor's quota. The server no longer stores a second identical copy.
    #[test]
    fn identical_redeposit_is_collapsed_and_does_not_grow_quota() {
        let s = Store::open_in_memory().unwrap();
        let sender = enroll(&s, b"send", "peerS");
        let recipient = enroll(&s, b"recv", "peerR");
        register(&s, &recipient, "mb_1");

        let first = s.deposit("mb_1", b"ayni-el-sikisma", &sender, 1, 1000).unwrap();
        for i in 2..50 {
            let again = s.deposit("mb_1", b"ayni-el-sikisma", &sender, i, 1000).unwrap();
            assert_eq!(again, first, "ayni zarf ayni seq'e dusmeli");
        }
        assert_eq!(s.mailbox_item_count("mb_1"), 1);

        // The quota must grow by only ONE copy. That was the actual crash.
        let e = s.enrollment_by_peer("peerS").unwrap();
        assert_eq!(e.bytes_mail as usize, mail_row_bytes("mb_1", b"ayni-el-sikisma"));

        // Different bytes still get separate rows.
        s.deposit("mb_1", b"baska-zarf", &sender, 60, 1000).unwrap();
        assert_eq!(s.mailbox_item_count("mb_1"), 2);
    }

    /// A client that did NOT register the box must be able to neither read nor delete from it. A first-contact box id
    /// is guessable, so without access control any enrolled party could fetch the mail and destroy it with `Ack`.
    #[test]
    fn unregistered_reader_can_neither_fetch_nor_ack() {
        let s = Store::open_in_memory().unwrap();
        let sender = enroll(&s, b"send", "peerS");
        let victim = enroll(&s, b"vict", "peerV");
        let snoop = enroll(&s, b"snoo", "peerN");
        register(&s, &victim, "mb_1");
        let seq = s.deposit("mb_1", b"gizli", &sender, 1, 1000).unwrap();

        let (stolen, _) = s.fetch(&snoop, &[("mb_1".into(), 0)], 10, 4096);
        assert!(stolen.is_empty(), "kaydetmemis istemci okuyamamali");
        assert_eq!(s.ack("mb_1", seq, &snoop).unwrap(), 0, "kaydetmemis istemci silememeli");
        assert_eq!(s.mailbox_item_count("mb_1"), 1, "posta yerinde kalmali");

        let (mine, _) = s.fetch(&victim, &[("mb_1".into(), 0)], 10, 4096);
        assert_eq!(mine.len(), 1, "gercek alici hala okuyabilmeli");
        assert_eq!(s.ack("mb_1", seq, &victim).unwrap(), 1);
    }

    #[test]
    fn a_full_box_is_counted_per_depositor() {
        let s = Store::open_in_memory().unwrap();
        let spam = enroll(&s, b"spam", "peerX");
        let real = enroll(&s, b"real", "peerR");
        let reader = enroll(&s, b"read", "peerD");
        register(&s, &reader, "mb_1");
        s.deposit("mb_1", b"a", &spam, 1, 1000).unwrap();
        s.deposit("mb_1", b"b", &spam, 1, 1000).unwrap();
        assert_eq!(s.depositor_item_count("mb_1", &spam), 2);
        assert_eq!(s.depositor_item_count("mb_1", &real), 0, "spam does not count against another sender");
    }

    /// A first-contact box id is derived from the fingerprint, so any enrolled party can register as a reader of it. That
    /// reader's `Ack` must not delete the real recipient's mail, and never acknowledging it must not fill the box.
    #[test]
    fn a_lurking_reader_can_neither_delete_nor_fill_anothers_mail() {
        let s = Store::open_in_memory().unwrap();
        let sender = enroll(&s, b"send", "peerS");
        let victim = enroll(&s, b"vict", "peerV");
        let lurker = enroll(&s, b"lurk", "peerL");
        register(&s, &victim, "mb_fp");
        register(&s, &lurker, "mb_fp");
        let seq = s.deposit("mb_fp", b"handshake", &sender, 1, 1000).unwrap();

        assert_eq!(s.ack("mb_fp", seq, &lurker).unwrap(), 0, "yabanci onayi silmemeli");
        let (mine, _) = s.fetch(&victim, &[("mb_fp".into(), 0)], 10, 4096);
        assert_eq!(mine.len(), 1, "alici postasini hala almali");

        // The recipient acks. If the stranger had not acked, the row would stay until the TTL but would not count toward
        // capacity. Here both acked.
        assert_eq!(s.ack("mb_fp", seq, &victim).unwrap(), 1);
        assert_eq!(s.mailbox_item_count("mb_fp"), 0);

        // A stranger that never acks: the row stays, but does not count toward capacity.
        let seq2 = s.deposit("mb_fp", b"handshake-2", &sender, 2, 1000).unwrap();
        // A third reader of the same key is refused: two per key, both in use.
        let third = enroll(&s, b"sile", "peerQ");
        let same_key = vec![("mb_fp".to_string(), b"test-key".to_vec())];
        assert_eq!(s.register_mailboxes_proved(&third, &["mb_fp".to_string()], &[], &same_key, 0, 100).unwrap().0.len(), 1);
        // The lurker is the silent reader here: it has not acked seq2.
        assert_eq!(s.ack("mb_fp", seq2, &victim).unwrap(), 0, "sessiz okuyucu varken silinmez");
        assert_eq!(s.mailbox_item_count("mb_fp"), 0, "alicinin onayladigi satir kapasiteye sayilmaz");
        assert_eq!(s.ack("mb_fp", seq2, &lurker).unwrap(), 1);
    }

    /// In the old version, re-enrolling opened a new `enrollment_id` and left the old reader rows ownerless. That owner
    /// could never acknowledge, and the mail was held until the TTL.
    #[test]
    fn orphaned_reader_does_not_block_deletion() {
        let s = Store::open_in_memory().unwrap();
        let sender = enroll(&s, b"send", "peerS");
        let reader = enroll(&s, b"read", "peerR");
        register(&s, &reader, "mb_1");
        register(&s, b"gone", "mb_1");
        let seq = s.deposit("mb_1", b"x", &sender, 1, 1000).unwrap();
        assert_eq!(s.ack("mb_1", seq, &reader).unwrap(), 1);
    }

    /// A ratchet box has TWO registered readers, and one does not overwrite the other's registration. The single-owner
    /// model used to break this.
    #[test]
    fn a_ratchet_mailbox_supports_two_registered_readers() {
        let s = Store::open_in_memory().unwrap();
        let a = enroll(&s, b"aaaa", "peerA");
        let b = enroll(&s, b"bbbb", "peerB");
        register(&s, &a, "mb_rt");
        register(&s, &b, "mb_rt");
        s.deposit("mb_rt", b"a->b", &a, 1, 1000).unwrap();
        s.deposit("mb_rt", b"b->a", &b, 2, 1000).unwrap();

        let (for_a, _) = s.fetch(&a, &[("mb_rt".into(), 0)], 10, 4096);
        assert_eq!(for_a.len(), 1);
        assert_eq!(for_a[0].sealed, b"b->a");
        let (for_b, _) = s.fetch(&b, &[("mb_rt".into(), 0)], 10, 4096);
        assert_eq!(for_b.len(), 1);
        assert_eq!(for_b[0].sealed, b"a->b");
    }

    /// The stride must be stored with the blob, or `serve_chunk` would read from the wrong offsets.
    #[test]
    fn blob_remembers_the_chunk_stride_it_was_written_with() {
        let s = Store::open_in_memory().unwrap();
        let a = enroll(&s, b"aaaa", "peerA");
        s.blob_begin("bl_s", &a, 2, 0).unwrap();
        assert_eq!(s.blob_state("bl_s").unwrap().chunk_size, 0, "baslangicta bilinmiyor");
        s.blob_set_chunk_size("bl_s", 512 * 1024);
        assert_eq!(s.blob_state("bl_s").unwrap().chunk_size, 512 * 1024);
        // The first value is FIXED. Later chunks cannot claim a different stride.
        s.blob_set_chunk_size("bl_s", 256 * 1024);
        assert_eq!(s.blob_state("bl_s").unwrap().chunk_size, 512 * 1024);
    }

    /// A global ceiling must also exist on top of the per-record quota.
    #[test]
    fn total_stored_bytes_counts_every_kind() {
        let s = Store::open_in_memory().unwrap();
        let a = enroll(&s, b"aaaa", "peerA");
        register(&s, &a, "mb_1");
        assert_eq!(s.total_stored_bytes(), 0);
        s.deposit("mb_1", &vec![b'x'; 100], &a, 1, 1000).unwrap();
        s.archive_put("ar_1", &[rec("m1", 1, 100, &vec![b'y'; 50])], &a, 0).unwrap();
        s.blob_begin("bl_1", &a, 1, 0).unwrap();
        s.blob_record_chunk("bl_1", 0, 25).unwrap();
        // 100 mail + its row + 50 archive + 2 for the record id "m1" + row + 25 blob.
        assert_eq!(s.total_stored_bytes(), 177 + (mail_row_bytes("mb_1", &[]) + ARCHIVE_ROW_OVERHEAD) as i64);
    }

    /// The sender must be able to withdraw its OWN undelivered packet, and only its own.
    #[test]
    fn sender_can_cancel_only_its_own_undelivered_deposit() {
        let s = Store::open_in_memory().unwrap();
        let sender = enroll(&s, b"send", "peerS");
        let other = enroll(&s, b"othr", "peerO");
        let recipient = enroll(&s, b"recv", "peerR");
        register(&s, &recipient, "mb_1");
        let mine = s.deposit("mb_1", b"benim", &sender, 1, 1000).unwrap();
        let theirs = s.deposit("mb_1", b"baskasinin", &other, 2, 1000).unwrap();

        // Cannot delete someone else's packet.
        assert_eq!(s.cancel_own_deposits("mb_1", &[theirs], &sender), 0);
        assert_eq!(s.mailbox_item_count("mb_1"), 2);
        // Can withdraw my own.
        assert_eq!(s.cancel_own_deposits("mb_1", &[mine], &sender), 1);
        assert_eq!(s.mailbox_item_count("mb_1"), 1);
        // The recipient still sees the other one.
        let (left, _) = s.fetch(&recipient, &[("mb_1".into(), 0)], 10, 4096);
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].sealed, b"baskasinin");
    }

    /// Operator decision: a BLOCK differs from a revoke. If the key is blocked, a fresh invite must not work either.
    #[test]
    fn blocking_is_keyed_on_the_enrollment_key_not_the_row() {
        let s = Store::open_in_memory().unwrap();
        let key = vec![9u8; 32];
        assert!(!s.is_key_blocked(&key));
        s.block_enrollment_key(&key, 0).unwrap();
        assert!(s.is_key_blocked(&key));
        // Another key is not affected.
        assert!(!s.is_key_blocked(&vec![8u8; 32]));
        s.unblock_enrollment_key(&key);
        assert!(!s.is_key_blocked(&key));
    }

    #[test]
    fn expired_mail_is_swept() {
        let s = Store::open_in_memory().unwrap();
        let a = enroll(&s, b"aaaa", "peerA");
        s.deposit("mb_1", b"x", &a, 1000, 10).unwrap();
        assert_eq!(s.sweep_expired_mail(1005), 0, "henuz dolmadi");
        assert_eq!(s.sweep_expired_mail(1010), 1);
    }

    #[test]
    fn archive_rows_expire_after_ttl() {
        let s = Store::open_in_memory().unwrap();
        let a = enroll(&s, b"a", "peerA");
        s.archive_put("ar_1", &[rec("m1", 1, 100, b"x")], &a, 1000).unwrap();
        assert_eq!(s.sweep_expired_archive(1000 + ARCHIVE_TTL_MS), 0);
        assert_eq!(s.sweep_expired_archive(1001 + ARCHIVE_TTL_MS), 1);
        assert!(s.archive_fetch("ar_1", None, 10, 65536).0.is_empty());
    }

    #[test]
    fn plain_db_migrates_to_sqlcipher() {
        let dir = std::env::temp_dir().join(format!("typeon_mig_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("typeon_server.db");
        set_db_key(None);
        { let s = Store::open(&p).unwrap(); s.meta_set("k", b"v").unwrap(); }
        set_db_key(Some(parse_hex_db_key(&"ab".repeat(32)).unwrap()));
        let s = Store::open(&p).unwrap();
        assert_eq!(s.meta_get("k").as_deref(), Some(&b"v"[..]));
        drop(s);
        set_db_key(None);
        assert!(Store::open(&p).is_err(), "plain open of an encrypted DB must fail");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Migration (I-48, K-41): an on-disk DB stamped at an older version and missing a later column gets it. A failing
    /// `ALTER` fails init and leaves the old stamp, so the next start retries. Opened without `Store::open`, so the global
    /// `DB_KEY` of the SQLCipher test cannot race this one.
    #[test]
    fn old_schema_gets_missing_column_or_stays_unstamped() {
        let dir = std::env::temp_dir().join(format!("typeon_schema_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("old.db");
        let open = || Store { conn: Connection::open(&p).unwrap() };
        let version = |s: &Store| s.conn.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0)).unwrap();
        let has_chunk_size = |s: &Store| {
            s.conn.query_row("SELECT COUNT(*) FROM pragma_table_info('blobs') WHERE name = 'chunk_size'", [], |r| r.get::<_, i64>(0)).unwrap() == 1
        };
        {
            let s = open();
            s.init_schema().unwrap();
            s.conn.execute_batch("ALTER TABLE blobs DROP COLUMN chunk_size; PRAGMA user_version = 3;").unwrap();
            assert!(!has_chunk_size(&s));
        }
        {
            let s = open();
            s.init_schema().unwrap();
            assert!(has_chunk_size(&s), "the missing column is added");
            assert_eq!(version(&s), SCHEMA_VERSION);
        }
        {
            // `ALTER TABLE mail ADD COLUMN` fails for a reason other than a duplicate column (a view cannot take one).
            let s = open();
            s.conn
                .execute_batch("DROP INDEX IF EXISTS idx_mail_hash; DROP TABLE mail; CREATE VIEW mail AS SELECT 1 AS seq; PRAGMA user_version = 3;")
                .unwrap();
            assert!(s.init_schema().is_err());
            assert_eq!(version(&s), 3, "a failed ALTER does not stamp the schema version");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The reader cap is per proof key. Two different keys on one first-contact box each get `MAX_READERS_PER_KEY`
    /// slots. A third reader of either key is refused while the two are in use.
    #[test]
    fn two_keys_on_one_box_each_take_two_readers() {
        let s = Store::open_in_memory().unwrap();
        let id = vec!["mb_1".to_string()];
        let proof = |key: &[u8]| vec![("mb_1".to_string(), key.to_vec())];
        let owners: Vec<Vec<u8>> = (0..6u8).map(|i| enroll(&s, &[b'a' + i; 4], &format!("peer{i}"))).collect();
        for (i, key) in [&b"key-1"[..], &b"key-2"[..]].into_iter().enumerate() {
            for o in &owners[i * 3..i * 3 + 2] {
                assert_eq!(s.register_mailboxes_proved(o, &id, &[], &proof(key), 0, 10).unwrap(), (vec![], vec![]));
            }
            assert_eq!(s.register_mailboxes_proved(&owners[i * 3 + 2], &id, &[], &proof(key), 0, 10).unwrap().0, id);
        }
        let readers = s.conn.query_row("SELECT COUNT(*) FROM mailbox_readers WHERE mailbox_id = 'mb_1'", [], |r| r.get::<_, i64>(0)).unwrap();
        assert_eq!(readers, 4);
    }

    #[test]
    fn archive_higher_rev_supersedes_lower() {
        let s = Store::open_in_memory().unwrap();
        let a = enroll(&s, b"aaaa", "peerA");
        s.archive_put("ar_1", &[rec("m1", 1, 100, b"ilk")], &a, 0).unwrap();
        s.archive_put("ar_1", &[rec("m1", 2, 100, b"duzeltilmis")], &a, 0).unwrap();
        let (page, _) = s.archive_fetch("ar_1", None, 10, 65536);
        assert_eq!(page.len(), 1, "ayni record_id tek satir olmali");
        assert_eq!(page[0].sealed, b"duzeltilmis");

        // A LOWER rev must not restore the old version (out-of-order delivery).
        s.archive_put("ar_1", &[rec("m1", 1, 100, b"ilk")], &a, 0).unwrap();
        let (page, _) = s.archive_fetch("ar_1", None, 10, 65536);
        assert_eq!(page[0].sealed, b"duzeltilmis");
    }

    #[test]
    fn archive_pages_newest_first_and_reports_more() {
        let s = Store::open_in_memory().unwrap();
        let a = enroll(&s, b"aaaa", "peerA");
        let records: Vec<_> = (0..5).map(|i| rec(&format!("m{i}"), 1, 100 + i, b"x")).collect();
        s.archive_put("ar_1", &records, &a, 0).unwrap();

        let (page, more) = s.archive_fetch("ar_1", None, 2, 65536);
        assert_eq!(page.len(), 2);
        assert!(more);
        assert_eq!(page[0].sent_at_ms, 104, "en yeni once");
        // Paging: from the newest seen to older.
        let (older, _) = s.archive_fetch("ar_1", Some((page[1].sent_at_ms, page[1].record_id.as_str())), 10, 65536);
        assert_eq!(older.len(), 3);
        assert!(older.iter().all(|r| r.sent_at_ms < page[1].sent_at_ms));
    }

    #[test]
    fn archive_probe_only_reports_non_empty_buckets() {
        let s = Store::open_in_memory().unwrap();
        let a = enroll(&s, b"aaaa", "peerA");
        s.archive_put("ar_full", &[rec("m1", 1, 100, b"x")], &a, 0).unwrap();
        let stats = s.archive_probe(&["ar_full".into(), "ar_empty".into()]);
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].bucket, "ar_full");
    }

    #[test]
    fn an_unlimited_invite_never_runs_out() {
        let s = Store::open_in_memory().unwrap();
        s.create_invite(b"pub", "herkese-acik", 0, 0, 0).unwrap();
        assert_eq!(s.invite_uses_left(b"pub", 0), Some(-1));
        for _ in 0..50 {
            assert!(s.consume_invite(b"pub", 10).unwrap(), "sinirsiz davet tukenmemeli");
        }
        assert_eq!(s.invite_uses_left(b"pub", 0), Some(-1), "sayac azalmamali");
        // The time limit still applies. Unlimited does NOT mean never expiring.
        s.create_invite(b"pub2", "gecici", 0, 100, 0).unwrap();
        assert!(!s.consume_invite(b"pub2", 200).unwrap());
    }

    #[test]
    fn a_deleted_invite_stops_working() {
        let s = Store::open_in_memory().unwrap();
        s.create_invite(b"pub", "herkese-acik", 0, 0, 0).unwrap();
        s.delete_invite(b"pub").unwrap();
        assert!(!s.consume_invite(b"pub", 10).unwrap(), "donen kod eskisini gecersiz kilmali");
        assert_eq!(s.invite_uses_left(b"pub", 0), None);
    }

    #[test]
    fn invite_uses_are_consumed_exactly_once() {
        let s = Store::open_in_memory().unwrap();
        s.create_invite(b"hash", "test", 1, 0, 0).unwrap();
        assert!(s.consume_invite(b"hash", 10).unwrap());
        assert!(!s.consume_invite(b"hash", 10).unwrap(), "tek kullanimlik olmali");
    }

    #[test]
    fn expired_invite_is_rejected() {
        let s = Store::open_in_memory().unwrap();
        s.create_invite(b"hash", "test", 5, 100, 0).unwrap();
        assert!(!s.consume_invite(b"hash", 200).unwrap());
        assert!(s.consume_invite(b"hash", 50).unwrap());
    }

    #[test]
    fn a_failed_enrollment_does_not_spend_the_invite() {
        let s = Store::open_in_memory().unwrap();
        s.create_invite(b"h", "x", 1, 0, 0).unwrap();
        enroll(&s, b"aaaa", "peerA");
        let e = s.enrollment_by_peer("peerA").unwrap();
        // Make the insert fail: there is no table to write to.
        s.conn.execute_batch("ALTER TABLE enrollments RENAME TO gone").unwrap();
        assert!(s.enroll_with_invite(b"h", 1, &e).is_err());
        s.conn.execute_batch("ALTER TABLE gone RENAME TO enrollments").unwrap();
        assert_eq!(s.invite_uses_left(b"h", 0), Some(1), "the use came back with the rollback");
        assert!(s.enroll_with_invite(b"h", 1, &e).unwrap());
        assert!(!s.enroll_with_invite(b"h", 1, &e).unwrap(), "spent");
    }

    #[test]
    fn enrollments_are_counted_per_invite() {
        let s = Store::open_in_memory().unwrap();
        s.create_invite(b"pub", "x", 0, 0, 0).unwrap();
        enroll(&s, b"aaaa", "peerA");
        enroll(&s, b"bbbb", "peerB");
        let a = s.enrollment_by_peer("peerA").unwrap();
        assert!(s.enroll_with_invite(b"pub", 1, &a).unwrap());
        assert_eq!(s.count_active_enrollments_via(b"pub", 0), 1, "peerB came in another way");
        assert_eq!(s.count_active_enrollments_via(b"rotated", 0), 0);
    }

    #[test]
    fn an_item_over_the_batch_cap_still_leaves_its_mailbox() {
        let s = Store::open_in_memory().unwrap();
        let a = enroll(&s, b"aaaa", "peerA");
        let b = enroll(&s, b"bbbb", "peerB");
        register(&s, &b, "mb_1");
        s.deposit("mb_1", &[7u8; 600], &a, 1, 1000).unwrap();
        s.deposit("mb_1", b"next", &a, 2, 1000).unwrap();
        let (items, more) = s.fetch(&b, &[("mb_1".into(), 0)], 10, 512);
        assert_eq!(items.len(), 1, "the oversized head goes out alone");
        assert!(more);
        let (items, more) = s.fetch(&b, &[("mb_1".into(), items[0].seq)], 10, 512);
        assert_eq!(items[0].sealed, b"next");
        assert!(!more);
    }

    #[test]
    fn archive_paging_walks_shared_timestamps_and_never_stalls() {
        let s = Store::open_in_memory().unwrap();
        let a = enroll(&s, b"aaaa", "peerA");
        s.archive_put("ar_1", &[rec("m1", 1, 100, b"a"), rec("m2", 1, 200, b"b"), rec("m3", 1, 200, b"c"), rec("m5", 1, 200, b"e"), rec("m4", 1, 300, b"d")], &a, 0).unwrap();
        // Walk the bucket two at a time, the way the client does.
        let mut seen = Vec::new();
        let mut before: Option<(u64, String)> = None;
        loop {
            let (page, more) = s.archive_fetch("ar_1", before.as_ref().map(|(ms, id)| (*ms, id.as_str())), 2, 65536);
            before = page.last().map(|r| (r.sent_at_ms, r.record_id.clone()));
            seen.extend(page.into_iter().map(|r| r.record_id));
            if !more {
                break;
            }
        }
        seen.sort();
        assert_eq!(seen, ["m1", "m2", "m3", "m4", "m5"], "a page may end inside the ts=200 group");
        // A record over the byte cap is still returned.
        let (page, _) = s.archive_fetch("ar_1", None, 10, 0);
        assert_eq!(page.len(), 1);
    }

    #[test]
    fn archive_charges_the_last_writer_and_any_holder_can_purge() {
        let s = Store::open_in_memory().unwrap();
        let a = enroll(&s, b"aaaa", "peerA");
        let b = enroll(&s, b"bbbb", "peerB");
        s.archive_put("ar_1", &[rec("m1", 1, 100, b"small")], &a, 0).unwrap();
        s.archive_put("ar_1", &[rec("m1", 2, 100, &[0u8; 1000])], &b, 0).unwrap();
        assert_eq!(s.enrollment_by_id(&a).unwrap().bytes_archive, 0);
        assert_eq!(s.enrollment_by_id(&b).unwrap().bytes_archive, 1002 + ARCHIVE_ROW_OVERHEAD as i64, "sealed + record_id + row");
        assert_eq!(s.archive_purge(&["ar_1".to_string()]), 1, "a's purge removes b's row");
        assert_eq!(s.enrollment_by_id(&b).unwrap().bytes_archive, 0);
    }

    #[test]
    fn deleting_a_blob_refunds_what_was_charged_and_frees_the_id() {
        let s = Store::open_in_memory().unwrap();
        let a = enroll(&s, b"aaaa", "peerA");
        s.blob_begin("bl_1", &a, 1, 0).unwrap();
        s.blob_record_chunk("bl_1", 0, 10).unwrap();
        s.add_blob_bytes(&a, 10);
        assert!(!s.blob_delete("bl_1", b"other"), "only the owner");
        assert!(s.blob_delete("bl_1", &a));
        assert_eq!(s.enrollment_by_id(&a).unwrap().bytes_blob, 0);
        assert!(!s.blob_has_chunk("bl_1", 0), "the id can be uploaded again");
    }

    #[test]
    fn rebind_moves_peer_and_frees_the_old_holder() {
        let s = Store::open_in_memory().unwrap();
        let a = enroll(&s, b"aaaa", "peerOld");
        enroll(&s, b"bbbb", "peerNew");
        s.rebind_enrollment(&a, "peerNew", 5).unwrap();
        let found = s.enrollment_by_peer("peerNew").unwrap();
        assert_eq!(found.enrollment_id, a, "yeni PeerId artik a kaydina cozulmeli");
        // A second displaced holder must not collide with the first one.
        let c = enroll(&s, b"cccc", "peerThird");
        enroll(&s, b"dddd", "peerFourth");
        s.rebind_enrollment(&c, "peerFourth", 6).unwrap();
        assert_eq!(s.enrollment_by_peer("peerFourth").unwrap().enrollment_id, c);
        assert!(s.revoke_enrollment(b"nope").is_err(), "a typo is not a revoke");
    }

    #[test]
    fn mailbox_quota_is_enforced_but_registration_is_idempotent() {
        let s = Store::open_in_memory().unwrap();
        let a = enroll(&s, b"aaaa", "peerA");
        s.register_mailboxes(&a, &["mb_1".into(), "mb_2".into()], &[], 0, 2).unwrap();
        // The refused id does not cost the batch: `mb_2` stays registered.
        assert_eq!(s.register_mailboxes(&a, &["mb_3".into(), "mb_2".into()], &[], 0, 2).unwrap(), ["mb_3"]);
        // Re-registering an id that is already registered must not hit the quota.
        assert!(s.register_mailboxes(&a, &["mb_1".into()], &[], 1, 2).unwrap().is_empty());
        s.register_mailboxes(&a, &[], &["mb_1".into()], 1, 2).unwrap();
        assert!(!s.mailbox_is_registered("mb_1"));
    }

    #[test]
    fn mail_bytes_are_recounted_after_delivery() {
        // If the quota grew one-way, an active user would get locked out within a few months.
        let s = Store::open_in_memory().unwrap();
        let sender = enroll(&s, b"send", "peerS");
        let recipient = enroll(&s, b"recv", "peerR");
        register(&s, &recipient, "mb_1");
        let seq = s.deposit("mb_1", &vec![b'x'; 500], &sender, 1, 1000).unwrap();
        assert_eq!(s.enrollment_by_peer("peerS").unwrap().bytes_mail, mail_row_bytes("mb_1", &[0; 500]) as i64);
        s.ack("mb_1", seq, &recipient).unwrap();
        s.recount_mail_bytes();
        assert_eq!(s.enrollment_by_peer("peerS").unwrap().bytes_mail, 0);
    }

    #[test]
    fn blob_is_only_complete_after_every_chunk() {
        let s = Store::open_in_memory().unwrap();
        let a = enroll(&s, b"aaaa", "peerA");
        s.blob_begin("bl_1", &a, 3, 0).unwrap();
        s.blob_record_chunk("bl_1", 0, 10).unwrap();
        s.blob_record_chunk("bl_1", 1, 10).unwrap();
        assert!(s.blob_finish("bl_1", b"hash", 5).is_err());
        assert!(!s.blob_state("bl_1").unwrap().complete, "eksik yukleme servis edilemez");
        s.blob_record_chunk("bl_1", 2, 10).unwrap();
        s.blob_finish("bl_1", b"hash", 5).unwrap();
        assert!(s.blob_state("bl_1").unwrap().complete);
    }

    #[test]
    fn out_of_order_chunks_are_accepted_and_counted() {
        // Chunks arrive out of order in the pipeline. The server must accept this and must not say 'complete' until all
        // of them have arrived.
        let s = Store::open_in_memory().unwrap();
        let a = enroll(&s, b"aaaa", "peerA");
        s.blob_begin("bl_1", &a, 3, 0).unwrap();
        s.blob_record_chunk("bl_1", 2, 10).unwrap();
        s.blob_record_chunk("bl_1", 0, 10).unwrap();
        assert!(s.blob_finish("bl_1", b"h", 5).is_err());
        assert!(!s.blob_state("bl_1").unwrap().complete, "eksik parcayla tamamlanmamali");
        assert_eq!(s.blob_state("bl_1").unwrap().received_chunks, 2);
        s.blob_record_chunk("bl_1", 1, 10).unwrap();
        s.blob_finish("bl_1", b"h", 5).unwrap();
        assert!(s.blob_state("bl_1").unwrap().complete);
        assert!(s.blob_has_chunk("bl_1", 1));
    }

    #[test]
    fn resent_blob_chunk_is_not_counted_twice() {
        let s = Store::open_in_memory().unwrap();
        let a = enroll(&s, b"aaaa", "peerA");
        s.blob_begin("bl_1", &a, 2, 0).unwrap();
        s.blob_record_chunk("bl_1", 0, 100).unwrap();
        s.blob_record_chunk("bl_1", 0, 100).unwrap();  // Connection dropped, retry.
        assert_eq!(s.blob_state("bl_1").unwrap().byte_len, 100, "tekrar gonderilen parca iki kez sayilmamali");
        s.blob_record_chunk("bl_1", 1, 100).unwrap();
        assert_eq!(s.blob_state("bl_1").unwrap().byte_len, 200);
    }

    #[test]
    fn blob_gc_spares_recently_served_files() {
        let s = Store::open_in_memory().unwrap();
        let a = enroll(&s, b"aaaa", "peerA");
        s.blob_begin("bl_1", &a, 1, 0).unwrap();
        s.blob_record_chunk("bl_1", 0, 10).unwrap();
        s.blob_finish("bl_1", b"h", 0).unwrap();
        assert!(s.blobs_to_gc(500, 1000).is_empty(), "TTL dolmadan silinmemeli");
        // A file still being downloaded must keep living.
        s.blob_touch("bl_1", 900);
        assert!(s.blobs_to_gc(1500, 1000).is_empty());
        assert_eq!(s.blobs_to_gc(2000, 1000), vec!["bl_1".to_string()]);
    }
}
