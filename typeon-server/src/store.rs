//! Sunucunun kalıcı deposu (SQLite).
//!
//! ## İki AYRI depo, kasıtlı olarak birleştirilmedi
//!
//! - `mail`: TESLİM kuyruğu. Mühürlü zarflar; alıcı `Ack`'leyince silinir,
//!   en fazla `mailbox_ttl_ms` yaşar.
//! - `archive`: GEÇMİŞ. Teslim zarfları burada KULLANILAMAZ — ratchet mesaj
//!   anahtarları ileri-gizli ve kullanıldıktan sonra siliniyor, yani geçen
//!   haftanın zarfı bugün HİÇ KİMSE tarafından çözülemez. Arşiv, istemcinin
//!   uzun ömürlü `archive_key`'iyle YENİDEN şifrelediği ayrı kayıtlardır.
//!
//! İkisini tek tabloda birleştirmek bu tasarımdaki en büyük hata olurdu:
//! "geçmişi sunucudan çek" özelliği sessizce çözülemeyen baytlar döndürürdü.
//!
//! ## Sunucu HİÇBİR ŞEY çözemez
//!
//! Buradaki her BLOB istemci tarafında şifrelenmiştir. Sunucunun gördüğü
//! yapısal alanlar bilinçli olarak asgari: opak kutu/kova kimlikleri, boyut,
//! zaman ve sıra numaraları. Bunların ne sızdırdığı SECURITY.md'de yazılı.

use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use std::path::Path;

// NOT: paket adı `p2p_messenger_core`, ama crate `p2p_messenger` adıyla
// linkleniyor (bkz. o crate'in `[lib] name`'i) — `use` yolu bu yüzden
// paket adından farklı.
use p2p_messenger::server_proto::{ArchiveRecord, BucketStat, MailItem};

/// Bir kaydın (enrollment) durumu.
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

/// Tek bir kayıtlı cihaz.
///
/// DİKKAT — burada bilerek OLMAYAN alanlar: `device_fingerprint`,
/// `identity_id`, cihazın kimlik public key'leri. Sunucunun gerçekten
/// ihtiyacı olan tek şey Sybil'e karşı bir kapı (davet jetonu) ve iptal
/// edilebilir bir tutamak (`enroll_pk`); geri kalanını istemek, operatöre
/// "bu sunucuyu tam olarak kimler kullanıyor" listesini kriptografik olarak
/// kanıtlanabilir biçimde vermek olurdu.
#[derive(Debug, Clone)]
pub struct Enrollment {
    pub enrollment_id: Vec<u8>,
    pub enroll_pk: Vec<u8>,
    /// ML-DSA-87 public key — kayıt imzası hibrit doğrulanıyor.
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
    /// Stride the blob was written with; 0 = legacy 256 KiB.
    pub chunk_size: u32,
}

pub struct Store {
    conn: Connection,
}

const MAX_READERS_PER_MAILBOX: i64 = 2;

impl Store {
    pub fn open(db_path: &Path) -> Result<Store, String> {
        let conn = Connection::open(db_path).map_err(|e| format!("DB açılamadı: {e}"))?;
        // Incremental auto-vacuum, so the file shrinks after mail is acked
        // (see `incremental_vacuum`). It only takes effect before the first
        // table exists or through one VACUUM, hence the one-time VACUUM on
        // a database created before this.
        let auto_vacuum: i64 = conn.pragma_query_value(None, "auto_vacuum", |r| r.get(0)).unwrap_or(2);
        if auto_vacuum != 2 {
            let _ = conn.pragma_update(None, "auto_vacuum", 2);
            let _ = conn.execute_batch("VACUUM");
        }
        // WAL: sunucu tek süreç ama okuma/yazma iç içe geçiyor; ayrıca ani
        // güç kesintisinde rollback journal'a göre çok daha dayanıklı.
        let _ = conn.pragma_update(None, "journal_mode", "WAL");
        let _ = conn.pragma_update(None, "synchronous", "NORMAL");
        // Defter #22: JNI kontrol yüzeyi (`serverStatus`/`joinCode`/
        // `listDevices`/`revokeDevice`) AYNI dosyaya İKİNCİ bir bağlantı
        // açıyor. WAL çoğu durumu kurtarıyor ama `busy_timeout` olmadan
        // çakışan yazmalar ANINDA `SQLITE_BUSY` dönüyordu — ve çağrı
        // yerlerinin neredeyse hepsi `let _ =`/`unwrap_or(0)` olduğu için
        // başarısız bir `deposit`/`ack`/`blob_record_chunk` SESSİZCE
        // yutuluyordu.
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

    /// Şema. Çekirdeğin `init_db`'siyle aynı sözleşme: `CREATE TABLE IF NOT
    /// EXISTS` + ileride eklenecek kolonlar için hatası yutulan `ALTER TABLE`.
    fn init_schema(&self) -> Result<(), String> {
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
                    PRIMARY KEY (mailbox_id, owner)
                );
                CREATE INDEX IF NOT EXISTS idx_reader_owner ON mailbox_readers(owner);

                -- The key a mailbox is bound to: hash of the public keys of
                -- the first `MailboxProof` registered for it.
                CREATE TABLE IF NOT EXISTS mailbox_keys (
                    mailbox_id TEXT PRIMARY KEY,
                    key_hash   BLOB NOT NULL
                );

                -- Mevcut kurulumlardan tek seferlik taşıma (idempotent).
                INSERT OR IGNORE INTO mailbox_readers (mailbox_id, owner, created_at, last_seen_at)
                    SELECT mailbox_id, owner, created_at, last_seen_at FROM mailboxes;
                DELETE FROM mailboxes;

                CREATE TABLE IF NOT EXISTS mail (
                    seq             INTEGER PRIMARY KEY AUTOINCREMENT,
                    mailbox_id      TEXT NOT NULL,
                    sealed          BLOB NOT NULL,
                    byte_len        INTEGER NOT NULL,
                    deposited_at_ms INTEGER NOT NULL,
                    expires_at_ms   INTEGER NOT NULL,
                    depositor       BLOB NOT NULL,
                    sealed_hash     BLOB
                );
                CREATE INDEX IF NOT EXISTS idx_mail_fetch ON mail(mailbox_id, seq);
                -- Replaced by `idx_mail_hash` (created below, after the column).
                DROP INDEX IF EXISTS idx_mail_dedup;
                CREATE INDEX IF NOT EXISTS idx_mail_expiry ON mail(expires_at_ms);
                -- Covering: `recount_mail_bytes` and `total_stored_bytes` sum
                -- from the index and never touch the `sealed` blobs.
                CREATE INDEX IF NOT EXISTS idx_mail_depositor ON mail(depositor, byte_len);

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

                -- Kullanıcı kararı: ENGELLENEN kayıt anahtarları. `revoke`
                -- yalnızca mevcut kaydı kapatır ve taze bir davetle geri
                -- dönüşe izin verir; engel ise anahtarın KENDİSİNE konur,
                -- yani aynı cihaz yeni bir davetle bile kaydolamaz.
                CREATE TABLE IF NOT EXISTS blocked_keys (
                    enroll_pk  BLOB PRIMARY KEY,
                    blocked_at INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v BLOB);
                "#,
            )
            .map_err(|e| format!("Şema oluşturulamadı: {e}"))?;
        // Mevcut kurulumlar için (kolon yoksa ekle; varsa hata yutulur).
        let _ = self.conn.execute("ALTER TABLE blobs ADD COLUMN chunk_size INTEGER NOT NULL DEFAULT 0", []);
        let _ = self.conn.execute("ALTER TABLE mail ADD COLUMN sealed_hash BLOB", []);
        // `deposit` finds a repeated item through this index alone.
        self.conn
            .execute_batch("CREATE INDEX IF NOT EXISTS idx_mail_hash ON mail(mailbox_id, depositor, sealed_hash)")
            .map_err(|e| format!("Şema oluşturulamadı: {e}"))?;
        Ok(())
    }

    /// bkz. defter #06 — ilk parçayla birlikte adımı sabitler.
    pub fn blob_set_chunk_size(&self, blob_id: &str, chunk_size: u32) {
        let _ = self.conn.execute(
            "UPDATE blobs SET chunk_size = ?2 WHERE blob_id = ?1 AND chunk_size = 0",
            params![blob_id, chunk_size as i64],
        );
    }

    /// Sunucunun o an sakladığı TOPLAM bayt (posta + arşiv + blob) —
    /// bkz. defter #23, kayıt başına kotanın üstündeki genel tavan.
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
    // meta
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
    // Davetler ve kayıt
    // -----------------------------------------------------------------

    /// Bir davet üretir. `uses <= 0` = SINIRSIZ (`-1` olarak saklanır).
    ///
    /// Kullanıcı isteği ("tek QR/link ile birden çok kişi katılabilmeli"):
    /// eskiden her yeni kişi için operatörün sunucuya gidip taze bir kod
    /// üretmesi gerekiyordu — davet tek kullanımlıktı ve Android sunucu
    /// arayüzü onu `uses=1` ile sabitliyordu. Sınırsız davet, kodun bir
    /// kere yayımlanıp (afiş, mesaj, web sayfası) herkesin kendi başına
    /// katılmasına izin verir. Sybil kapısı kaybolmaz, YER DEĞİŞTİRİR:
    /// artık jetonun kendisi değil, `ServerCore::handle_enroll` içindeki
    /// saatlik kayıt tavanı (`MAX_PUBLIC_ENROLLMENTS_PER_HOUR`) ve
    /// operatörün kodu istediği an döndürebilmesi (`rotate_join_code`)
    /// koruyor.
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

    /// Bir daveti siler — `rotate_join_code` eski herkese açık kodu
    /// geçersiz kılarken kullanır.
    pub fn delete_invite(&self, token_hash: &[u8]) -> Result<(), String> {
        self.conn
            .execute("DELETE FROM invites WHERE token_hash = ?1", params![token_hash])
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// Kalan kullanım hakkı: `Some(-1)` sınırsız, `Some(0)` tükenmiş,
    /// `None` böyle bir davet yok ya da süresi dolmuş.
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

    /// `since`'ten (dahil değil) beri açılan kayıt sayısı — herkese açık
    /// davetin saatlik tavanı için.
    pub fn count_enrollments_since(&self, since: i64) -> i64 {
        self.conn
            .query_row("SELECT COUNT(*) FROM enrollments WHERE enrolled_at > ?1", params![since], |r| r.get(0))
            .unwrap_or(0)
    }

    /// Active enrollments seen at or after `idle_before`: a sleeping one
    /// (see `sleep_idle_enrollments`) holds no place under the cap.
    pub fn count_active_enrollments(&self, idle_before: i64) -> i64 {
        self.conn
            .query_row(
                "SELECT COUNT(*) FROM enrollments WHERE state = 'active' AND last_seen_at >= ?1",
                params![idle_before],
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
            // `uses_left` artık İŞARETLİ: `-1` sınırsız (bkz.
            // `create_invite`). `u32`'ye çevirmek onu 4 milyara döndürürdü.
            let uses: i64 = r.get(1)?;
            let exp: i64 = r.get(2)?;
            Ok((label, uses, exp, uses != 0 && (exp == 0 || exp > now)))
        });
        rows.map(|it| it.filter_map(|r| r.ok()).collect()).unwrap_or_default()
    }

    /// Bir daveti TÜKETİR (kullanım hakkını bir azaltır) — geçerliyse `true`.
    ///
    /// Kullanım sayacının azaltılması ve kaydın oluşturulması AYNI çağrı
    /// zincirinde olmalı; aksi halde eşzamanlı iki `Enroll` tek kullanımlık
    /// bir jetonu iki kez harcayabilirdi. `UPDATE ... WHERE uses_left > 0`
    /// tek bir atomik ifade olduğundan bu yarış SQLite seviyesinde kapanıyor.
    pub fn consume_invite(&self, token_hash: &[u8], now: i64) -> Result<bool, String> {
        let changed = self
            .conn
            .execute(
                // `uses_left = -1` SINIRSIZ: tüketilir ama azalmaz (bkz.
                // `create_invite`). `<> 0` koşulu hem tükenmiş (0) hem de
                // sınırsız (-1) daveti tek ifadede doğru ayırır.
                "UPDATE invites SET uses_left = CASE WHEN uses_left < 0 THEN uses_left ELSE uses_left - 1 END
                 WHERE token_hash = ?1 AND uses_left <> 0 AND (expires_at = 0 OR expires_at > ?2)",
                params![token_hash, now],
            )
            .map_err(|e| e.to_string())?;
        Ok(changed > 0)
    }

    /// Consumes one invite use and writes the enrollment: both or neither.
    /// `Ok(false)`: the invite is spent, expired or gone.
    pub fn enroll_with_invite(&self, token_hash: &[u8], now: i64, e: &Enrollment) -> Result<bool, String> {
        let tx = self.conn.unchecked_transaction().map_err(|e| e.to_string())?;
        if !self.consume_invite(token_hash, now)? {
            return Ok(false);
        }
        self.insert_enrollment(e)?;
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

    /// `Rebind`: var olan bir kaydı yeni bir `PeerId`'ye taşı.
    pub fn rebind_enrollment(&self, enrollment_id: &[u8], new_peer_id: &str, now: i64) -> Result<(), String> {
        // Aynı PeerId'ye bağlı BAŞKA bir kayıt varsa önce onu çöz — `peer_id`
        // UNIQUE, aksi halde INSERT çakışırdı (uygulamayı silip yeniden kuran
        // bir cihaz aynı libp2p anahtarını yeniden üretebilir). The placeholder
        // is unique per row: a shared '' broke the index on the second collision.
        let _ = self.conn.execute(
            "UPDATE enrollments SET peer_id = 'unbound:' || hex(enrollment_id) WHERE peer_id = ?1 AND enrollment_id != ?2",
            params![new_peer_id, enrollment_id],
        );
        self.conn
            .execute(
                "UPDATE enrollments SET peer_id = ?1, last_seen_at = ?2 WHERE enrollment_id = ?3",
                params![new_peer_id, now, enrollment_id],
            )
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// Revoke is a block: the enroll key goes on the block list, and the row
    /// stays, so `handle_enroll` finds the blocked key for this PeerId too.
    pub fn revoke_enrollment(&self, enrollment_id: &[u8]) -> Result<(), String> {
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
            .and_then(|n| if n == 0 { Err("Kayıt bulunamadı".to_string()) } else { Ok(()) })
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
    // Posta kutusu
    // -----------------------------------------------------------------

    /// Tests: every id comes with a proof by one shared key.
    #[cfg(test)]
    pub fn register_mailboxes(&self, owner: &[u8], add: &[String], drop: &[String], now: i64, max: u32) -> Result<Vec<String>, String> {
        let proofs: Vec<(String, Vec<u8>)> = add.iter().map(|id| (id.clone(), b"test-key".to_vec())).collect();
        self.register_mailboxes_proved(owner, add, drop, &proofs, now, max).map(|(refused, _)| refused)
    }

    /// `Ok`: the ids of `add` that were refused (mailbox quota, reader cap,
    /// a proof by another key than the mailbox is bound to), then the ids
    /// that need a proof and came without one. The other ids are registered:
    /// one refused id does not cost the batch.
    ///
    /// `proofs`: (mailbox id, hash of the mailbox key) of each `MailboxProof`
    /// whose signature the caller verified. An id `owner` reads already needs
    /// none. The first proof binds the mailbox to its key (`mailbox_keys`).
    pub fn register_mailboxes_proved(
        &self,
        owner: &[u8],
        add: &[String],
        drop: &[String],
        proofs: &[(String, Vec<u8>)],
        now: i64,
        max: u32,
    ) -> Result<(Vec<String>, Vec<String>), String> {
        let mut refused = Vec::new();
        let mut unproven = Vec::new();
        for id in add {
            let count: i64 = self
                .conn
                .query_row("SELECT COUNT(*) FROM mailbox_readers WHERE owner = ?1", params![owner], |r| r.get(0))
                .unwrap_or(0);
            // Zaten kayıtlıysa sayaç kontrolünü atla — idempotent olmalı.
            //
            // Bu denetimde bulundu: sorgu `owner`'ı FİLTRELEMİYORDU, oysa
            // `mailbox_readers` çok-okuyuculu (bkz. şema notu) — yani
            // BAŞKA birinin kaydettiği bir kutu bu istemci için de "zaten
            // var" sayılıyor ve `max_mailboxes` kotası atlanıyordu. Bir
            // ratchet kutusunu iki taraf da kaydettiğinden bu istisnai bir
            // durum değil, NORMAL durum: pratikte kota, ikinci tarafta
            // hiçbir zaman uygulanmıyordu.
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
            // A mailbox has at most two readers: both ends of a session, or
            // the one device of a first-contact box. Without the cap any number
            // of enrolled clients could lurk on a box whose id they computed.
            if !exists {
                let readers: i64 = self
                    .conn
                    .query_row("SELECT COUNT(*) FROM mailbox_readers WHERE mailbox_id = ?1", params![id], |r| r.get(0))
                    .unwrap_or(0);
                if readers >= MAX_READERS_PER_MAILBOX {
                    refused.push(id.clone());
                    continue;
                }
                let Some((_, key_hash)) = proofs.iter().find(|(m, _)| m == id) else {
                    unproven.push(id.clone());
                    continue;
                };
                let bound: Option<Vec<u8>> = self
                    .conn
                    .query_row("SELECT key_hash FROM mailbox_keys WHERE mailbox_id = ?1", params![id], |r| r.get(0))
                    .optional()
                    .map_err(|e| e.to_string())?;
                match bound {
                    Some(k) if &k != key_hash => {
                        refused.push(id.clone());
                        continue;
                    }
                    Some(_) => {}
                    None => {
                        self.conn
                            .execute("INSERT INTO mailbox_keys (mailbox_id, key_hash) VALUES (?1, ?2)", params![id, key_hash])
                            .map_err(|e| e.to_string())?;
                    }
                }
            }
            // Defter #03: kayıt artık ÇOK-OKUYUCULU (bkz. `mailbox_readers`
            // şema notu). Aynı ratchet kutusunu iki taraf da kaydeder;
            // birinin kaydı diğerininkini EZMEZ.
            self.conn
                .execute(
                    "INSERT INTO mailbox_readers (mailbox_id, owner, created_at, last_seen_at)
                     VALUES (?1, ?2, ?3, ?3)
                     ON CONFLICT(mailbox_id, owner) DO UPDATE SET last_seen_at = ?3",
                    params![id, owner, now],
                )
                .map_err(|e| e.to_string())?;
        }
        for id in drop {
            // SADECE sahibi kaldırabilir. Not a reader: nothing changed, and
            // the cleanup below is a scan of the whole box.
            let left = self
                .conn
                .execute("DELETE FROM mailbox_readers WHERE mailbox_id = ?1 AND owner = ?2", params![id, owner])
                .unwrap_or(0);
            if left == 0 {
                continue;
            }
            // Ayrılan okuyucu artık silmeyi bekletmesin; kendi onayı bu
            // temizlikte hâlâ sayılır, sonra imleci atılır.
            let _ = self.delete_fully_acked(id);
            let _ = self
                .conn
                .execute("DELETE FROM mail_acks WHERE mailbox_id = ?1 AND owner = ?2", params![id, owner]);
        }
        Ok((refused, unproven))
    }

    pub fn mailbox_is_registered(&self, mailbox_id: &str) -> bool {
        self.conn
            .query_row("SELECT 1 FROM mailbox_readers WHERE mailbox_id = ?1", params![mailbox_id], |_| Ok(true))
            .optional()
            .ok()
            .flatten()
            .unwrap_or(false)
    }

    /// Kutu kapasitesi için: henüz HİÇBİR alıcı okuyucunun onaylamadığı
    /// satırlar. Onaylanmış ama başka bir (ör. hiç onaylamayan yabancı)
    /// okuyucu yüzünden TTL'e kadar duran satırlar sayılmaz — aksi halde o
    /// okuyucu kutuyu doldurup yeni teslimleri kilitlerdi.
    /// ponytail: bu satırlar bayt kotasına (`recount_mail_bytes`) hâlâ sayılır;
    /// kötü niyetli okuyucular diski TTL boyunca yalnızca kota kadar tutabilir.
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

    /// Aynı kutuda, aynı bırakanın AYNI baytları zaten duruyorsa yeni satır
    /// AÇILMAZ — mevcut `seq` döner.
    ///
    /// Gerçek cihazda ölçülen çöküş (2026-08-29): istemci tarafındaki
    /// tekilleştirme yalnızca `Message` zarflarını tanıyordu, bu yüzden bir
    /// `Handshake` saniyede bir kez (~15 KB) yeniden yatırılıyor ve bırakanın
    /// `bytes_mail` kotasını saatler içinde doldurup o cihazın TÜM
    /// store-and-forward trafiğini kilitliyordu (bkz. istemci
    /// `deposit_dedup_key`). İstemci düzeltildi; bu kontrol ikinci savunma
    /// katmanı: eski/hatalı bir istemci de artık sunucuyu şişiremez.
    ///
    /// Tekrarı ATMAK güvenli: alıcı zaten `message_id` ile tekilleştiriyor ve
    /// birebir aynı ciphertext'in ikinci kopyası hiçbir bilgi taşımıyor.
    pub fn deposit(&self, mailbox_id: &str, sealed: &[u8], depositor: &[u8], now: i64, ttl_ms: i64) -> Result<u64, String> {
        // By hash, from the index: comparing `sealed` itself read every
        // same-length blob of this depositor in the box on each deposit.
        let hash = Sha256::digest(sealed);
        if let Ok(existing) = self.conn.query_row(
            "SELECT seq FROM mail WHERE mailbox_id = ?1 AND depositor = ?2 AND sealed_hash = ?3 LIMIT 1",
            params![mailbox_id, depositor, hash.as_slice()],
            |row| row.get::<_, i64>(0),
        ) {
            // TTL'i tazele — gönderen hâlâ ısrar ediyorsa alıcı henüz almamış
            // demektir, kopyanın erken düşmesini istemeyiz.
            let _ = self.conn.execute(
                "UPDATE mail SET expires_at_ms = ?1 WHERE seq = ?2",
                params![now + ttl_ms, existing],
            );
            return Ok(existing as u64);
        }
        self.conn
            .execute(
                "INSERT INTO mail (mailbox_id, sealed, byte_len, deposited_at_ms, expires_at_ms, depositor, sealed_hash)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![mailbox_id, sealed, sealed.len() as i64, now, now + ttl_ms, depositor, hash.as_slice()],
            )
            .map_err(|e| e.to_string())?;
        let seq = self.conn.last_insert_rowid() as u64;
        // Kota BIRAKANA yazılır, kutunun SAHİBİNE değil — bir spam gönderici
        // kendi kotasını yakar; kimse bir kurbanın kutusunu doldurup ona
        // hizmet reddi uygulayamaz.
        let _ = self.conn.execute(
            "UPDATE enrollments SET bytes_mail = bytes_mail + ?1 WHERE enrollment_id = ?2",
            params![sealed.len() as i64, depositor],
        );
        Ok(seq)
    }

    /// İmleçten sonraki öğeleri çeker. `max_bytes`/`max_items` aşılmadan
    /// önce durur; kalanı bir sonraki turda gelir (`more`).
    ///
    /// `requester`: isteyenin kayıt kimliği. KENDİ bıraktığı zarflar
    /// DÖNDÜRÜLMEZ — bir ratchet kutusunu iki taraf da hem yazan hem okuyan
    /// olarak kullanıyor, filtre olmadan herkes kendi giden trafiğini geri
    /// indirir, çözemez (gönderme zinciriyle alma zinciri farklı), ve log'u
    /// "çözülemedi" hatalarıyla doldurur. Bant genişliği ve CPU boşa gider.
    pub fn fetch(&self, requester: &[u8], cursors: &[(String, u64)], max_items: u32, max_bytes: u32) -> (Vec<MailItem>, bool) {
        let mut items = Vec::new();
        let mut total = 0usize;
        let mut more = false;

        // Defter #03: yalnızca kutuyu KAYDETMİŞ bir okuyucu okuyabilir.
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
            let rows = stmt.query_map(params![mailbox_id, *after_seq as i64, requester], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, Vec<u8>>(2)?))
            });
            let Ok(rows) = rows else { continue };
            for (seq, deposited_at_ms, sealed) in rows.flatten() {
                // The first item always goes out, even over `max_bytes`: an
                // item larger than the batch cap otherwise blocks its mailbox
                // (zero items, `more` forever) until the TTL.
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

    /// Kümülatif silme.
    ///
    /// SADECE zarfı BIRAKMAYAN taraf silebilir. Grup mesajlaşması pairwise
    /// olduğundan bir `mb_*` kutusunun olası okuyucusu TAM OLARAK ikidir ve
    /// biri bırakandır — dolayısıyla "bütün aboneler onayladı mı" gibi bir
    /// muhasebeye hiç gerek yok. Bırakanın kendi `Ack`'i sessizce yok sayılır
    /// (aksi halde gönderen, alıcı görmeden mesajı silebilirdi).
    /// Items in `mailbox_id` that `reader` has not acknowledged (and did not
    /// deposit itself) — see `ServerRequest::Push`.
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
        // Defter #03: yalnızca kutuyu KAYDETMİŞ bir okuyucu onaylayabilir.
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
        // Clamped to what the box holds: an ack of a future seq otherwise
        // covered every later item too.
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
        // The cursor did not move: nothing new to delete, and the delete is a
        // scan of the whole box (a repeated ack ran it 512 times per request).
        if moved == 0 {
            return Ok(0);
        }
        self.delete_fully_acked(mailbox_id)
    }

    /// Bırakan dışındaki BÜTÜN kayıtlı okuyucuların onayladığı (ve en az
    /// birinin gerçekten onayladığı) satırları siler. Onaylamayan bir okuyucu
    /// (ör. kutuya kaydolmuş bir yabancı) satırı TTL'e kadar tutar ama
    /// başkasının postasını silemez.
    fn delete_fully_acked(&self, mailbox_id: &str) -> Result<usize, String> {
        self.conn
            .execute(
                "DELETE FROM mail WHERE mailbox_id = ?1
                   AND EXISTS (SELECT 1 FROM mail_acks a
                               WHERE a.mailbox_id = mail.mailbox_id AND a.owner != mail.depositor
                                 AND a.through_seq >= mail.seq)
                   AND NOT EXISTS (SELECT 1 FROM mailbox_readers r
                                   WHERE r.mailbox_id = mail.mailbox_id AND r.owner != mail.depositor
                                     AND r.owner IN (SELECT enrollment_id FROM enrollments WHERE state = 'active')
                                     AND COALESCE((SELECT a.through_seq FROM mail_acks a
                                                   WHERE a.mailbox_id = r.mailbox_id AND a.owner = r.owner), 0) < mail.seq)",
                params![mailbox_id],
            )
            .map_err(|e| e.to_string())
    }

    /// Süresi dolmuş teslim öğelerini siler. Onaya ek bir emniyet kemeri:
    /// hiç geri dönmeyen bir alıcı yüzünden kutu sonsuza dek büyümesin.
    /// bkz. `ServerRequest::Cancel` — gönderen, HENÜZ TESLİM EDİLMEMİŞ
    /// kendi paketini geri çeker. `depositor = ?3` şartı kritik: yalnızca
    /// kendi bıraktığınızı silebilirsiniz, başkasınınkini asla.
    pub fn cancel_own_deposits(&self, mailbox_id: &str, seqs: &[u64], depositor: &[u8]) -> usize {
        let mut removed = 0usize;
        for seq in seqs {
            removed += self
                .conn
                .execute(
                    "DELETE FROM mail WHERE mailbox_id = ?1 AND seq = ?2 AND depositor = ?3",
                    params![mailbox_id, *seq as i64, depositor],
                )
                .unwrap_or(0);
        }
        removed
    }

    /// bkz. `ServerRequest::Block` / defter dışı kullanıcı kararı: iptal
    /// (`revoke`) yeni bir davetle geri dönmeye izin verir, ENGEL vermez.
    /// Engel, kayıt anahtarının kendisine konur; aynı anahtarla yeni bir
    /// kayıt açılamaz.
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
        // Kaydı silinmiş/iptal edilmiş sahiplerin okuyucu satırları: artık
        // onaylayamazlar, `delete_fully_acked` onları zaten saymıyor; bekleyen
        // postayı bırakmak için kutuları yeniden değerlendir.
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
        // A mailbox nobody reads is free again: its key binding goes.
        let _ = self.conn.execute(
            "DELETE FROM mailbox_keys WHERE mailbox_id NOT IN (SELECT mailbox_id FROM mailbox_readers)",
            [],
        );
        removed
            + self
                .conn
                .execute("DELETE FROM mail WHERE expires_at_ms <= ?1", params![now])
                .unwrap_or(0)
    }

    // -----------------------------------------------------------------
    // Arşiv
    // -----------------------------------------------------------------

    /// Kayıtları yükler/üzerine yazar.
    ///
    /// `WHERE excluded.rev > archive.rev`: bir düzenleme/silme AYNI
    /// `record_id`'yi taşır ve daha yüksek bir `rev` ile eskisinin üzerine
    /// yazar. Bu, mevcut `HistorySyncResponse` mekanizmasının YAPAMADIĞI bir
    /// şeydir (geç gelen bir Edit'i geçmişte düzeltmek). Aynı kural, N
    /// cihazımın AYNI kaydı yüklemesini de tek satıra indirir.
    ///
    /// The last writer becomes `owner` and pays for the row. The quota counts
    /// `sealed` plus `record_id`, the two peer-sized columns.
    pub fn archive_put(&self, bucket: &str, records: &[ArchiveRecord], owner: &[u8], now: i64) -> Result<u64, String> {
        let mut newest = 0u64;
        // Whose charge changes: the writer and the owners it overwrites.
        let mut owners = vec![owner.to_vec()];
        // One transaction: one WAL commit per batch, and all or nothing.
        let tx = self.conn.unchecked_transaction().map_err(|e| e.to_string())?;
        for rec in records {
            // Skipped, not refused: the client drops what was answered `Ok`,
            // and one over-long id must not block its archive queue.
            if rec.record_id.len() > 128 {
                continue;
            }
            let old = self.conn.query_row(
                "SELECT owner FROM archive WHERE bucket = ?1 AND record_id = ?2",
                params![bucket, rec.record_id],
                |r| r.get::<_, Vec<u8>>(0),
            );
            if let Ok(old) = old {
                if !owners.contains(&old) {
                    owners.push(old);
                }
            }
            self.conn
                .execute(
                    "INSERT INTO archive (bucket, record_id, rev, sent_at_ms, sealed, byte_len, owner, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                     ON CONFLICT(bucket, record_id) DO UPDATE SET
                        rev = excluded.rev, sent_at_ms = excluded.sent_at_ms,
                        sealed = excluded.sealed, byte_len = excluded.byte_len,
                        owner = excluded.owner, updated_at = excluded.updated_at
                     WHERE excluded.rev > archive.rev",
                    params![bucket, rec.record_id, rec.rev.min(i64::MAX as u64) as i64, rec.sent_at_ms as i64, rec.sealed, (rec.sealed.len() + rec.record_id.len()) as i64, owner, now],
                )
                .map_err(|e| e.to_string())?;
            newest = newest.max(rec.rev);
        }
        tx.commit().map_err(|e| e.to_string())?;
        self.recount_archive_bytes(&owners);
        Ok(newest)
    }

    /// Only the owners whose rows changed (an overwrite or a purge changes
    /// what another enrollment is charged for). Over every enrollment it was
    /// a scan of the whole archive on each request.
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
        for b in buckets {
            let row = self.conn.query_row(
                "SELECT COUNT(*), COALESCE(MIN(sent_at_ms),0), COALESCE(MAX(sent_at_ms),0) FROM archive WHERE bucket = ?1",
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

    /// Yeniden eskiye bir sayfa. `before_ms: None` = en yeni sayfa.
    ///
    /// The client continues with `before_ms` = the oldest `sent_at_ms` it got,
    /// so a page never ends inside a group of records that share a timestamp:
    /// the rest of that group would be skipped.
    /// ponytail: a group that fills a page alone is cut at 4x `max_items` /
    /// 2x `max_bytes` and the client never sees its rest; add a
    /// `(sent_at_ms, record_id)` cursor to the protocol if that ever matters.
    pub fn archive_fetch(&self, bucket: &str, before_ms: Option<u64>, max_items: u32, max_bytes: u32) -> (Vec<ArchiveRecord>, bool) {
        let before = before_ms.map(|v| v as i64).unwrap_or(i64::MAX);
        let mut stmt = match self.conn.prepare(
            "SELECT record_id, rev, sent_at_ms, sealed FROM archive
             WHERE bucket = ?1 AND sent_at_ms < ?2 ORDER BY sent_at_ms DESC",
        ) {
            Ok(s) => s,
            Err(_) => return (Vec::new(), false),
        };
        let rows = stmt.query_map(params![bucket, before], |r| {
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
            // `!out.is_empty()`: the first record always goes out, or one
            // record over `max_bytes` hides everything older in its bucket.
            let full = !out.is_empty()
                && (out.len() as u32 >= max_items || total + rec.sealed.len() > max_bytes as usize);
            if full && out[0].sent_at_ms != rec.sent_at_ms {
                // Hand the split timestamp group to the next page as a whole.
                out.retain(|r| r.sent_at_ms != rec.sent_at_ms);
                return (out, true);
            }
            // The page is one timestamp group. Without a hard stop a client
            // that put its whole quota under one `sent_at_ms` got it back in
            // one response, all of it in memory.
            if full
                && (out.len() as u32 >= max_items.saturating_mul(4)
                    || total + rec.sealed.len() > (max_bytes as usize).saturating_mul(2))
            {
                return (out, true);
            }
            total += rec.sealed.len();
            out.push(rec);
        }
        (out, false)
    }

    /// Deletes whole buckets, whoever uploaded the rows. The bucket id is the
    /// capability, as it is for `archive_fetch` and for overwriting a record:
    /// a chat deleted on one linked device goes for all of them.
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
    // Blob (dosya eki)
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

    /// Bu parça daha önce geldi mi? (Boru hattında tekrar gönderim olabilir.)
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
        // `received_chunks` bir SAYAÇ değil, bir SU SEVİYESİ: parçalar sıralı
        // yükleniyor (istemci tek seferde tek `BlobPut` tutuyor), bu yüzden
        // "en yüksek görülen index + 1" doğru ve tekrar gönderilen bir parça
        // sayacı yanlışlıkla ilerletmiyor.
        // Parça kaydı İDEMPOTENT: aynı indeks tekrar gelirse (bağlantı
        // koptu, istemci yeniden gönderdi) ne sayaç ne bayt iki kez artar.
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
        // `received_chunks` artık GERÇEK bir sayım — su seviyesi değil, ki
        // boru hattında parçalar sırasız geliyor.
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

    pub fn blob_finish(&self, blob_id: &str, enc_sha256: &[u8], now: i64) -> Result<(), String> {
        self.conn
            .execute(
                "UPDATE blobs SET complete = 1, enc_sha256 = ?2, last_served_at = ?3
                 WHERE blob_id = ?1 AND received_chunks >= total_chunks",
                params![blob_id, enc_sha256, now],
            )
            .map(|_| ())
            .map_err(|e| e.to_string())
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

    /// `true` if `owner` owned the blob; the caller then removes the file.
    pub fn blob_delete(&self, blob_id: &str, owner: &[u8]) -> bool {
        let owned = self.blob_state(blob_id).map_or(false, |s| s.owner == owner);
        if owned {
            self.blob_forget(blob_id);
        }
        owned
    }

    /// Silinmesi gereken blob kimliklerini döner (dosyaları çağıran siler).
    ///
    /// İki kural: tamamlanmışlar `blob_ttl_ms` boyunca SON SERVİSTEN sonra
    /// yaşar (indirilmeye devam eden bir dosya yaşamaya devam eder — dış
    /// incelemedeki #4 maddesinin istediği davranış), yarım kalmış
    /// yüklemeler son parçadan 24 saat sonra atılır (`blob_touch` per chunk).
    pub fn blobs_to_gc(&self, now: i64, ttl_ms: i64) -> Vec<String> {
        let mut stmt = match self.conn.prepare(
            "SELECT blob_id FROM blobs
             WHERE (complete = 1 AND last_served_at + ?1 <= ?2)
                OR (complete = 0 AND last_served_at + 86400000 <= ?2)",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        stmt.query_map(params![ttl_ms, now], |r| r.get::<_, String>(0))
            .map(|it| it.filter_map(|r| r.ok()).collect())
            .unwrap_or_default()
    }

    /// The one way a blob leaves the DB: refunds the owner exactly the bytes
    /// charged (`byte_len`, not the file length: a sparse file is far longer
    /// than what was paid for) and drops the chunk rows with the blob row.
    pub fn blob_forget(&self, blob_id: &str) {
        let _ = self.conn.execute(
            "UPDATE enrollments SET bytes_blob = MAX(0, bytes_blob - (SELECT byte_len FROM blobs WHERE blob_id = ?1))
             WHERE enrollment_id = (SELECT owner FROM blobs WHERE blob_id = ?1)",
            params![blob_id],
        );
        let _ = self.conn.execute("DELETE FROM blobs WHERE blob_id = ?1", params![blob_id]);
        let _ = self.conn.execute("DELETE FROM blob_chunks WHERE blob_id = ?1", params![blob_id]);
    }

    // -----------------------------------------------------------------
    // Kota
    // -----------------------------------------------------------------

    pub fn add_blob_bytes(&self, owner: &[u8], delta: i64) {
        let _ = self.conn.execute(
            "UPDATE enrollments SET bytes_blob = MAX(0, bytes_blob + ?1) WHERE enrollment_id = ?2",
            params![delta, owner],
        );
    }

    /// Silinen teslim öğelerinin baytını bırakanların kotasından düşer.
    /// `ack`/`sweep_expired_mail` sonrası çağrılır — aksi halde kota tek
    /// yönlü artar ve aktif bir kullanıcı birkaç ayda sunucudan kilitlenirdi.
    pub fn recount_mail_bytes(&self) {
        let _ = self.conn.execute_batch(
            "UPDATE enrollments SET bytes_mail =
                COALESCE((SELECT SUM(byte_len) FROM mail WHERE mail.depositor = enrollments.enrollment_id), 0);",
        );
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

    /// Bir kutuyu okuyabilmek icin KAYIT sart (bkz. defter #03 /
    /// `mailbox_readers`). Gercek akista `Register` her zaman `Fetch`ten
    /// once gelir — testler bu adimi atliyordu.
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

    /// Revoke = block: the key is refused until the operator unblocks it, and
    /// the revoked row stays so the PeerId still leads to the blocked key.
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

    /// Owner decision K3: an idle enrollment sleeps, it is not removed.
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
        // İmleci ilerlet — aynı öğeler bir daha gelmemeli.
        let (again, _) = s.fetch(&b, &[("mb_1".into(), s2)], 10, 4096);
        assert!(again.is_empty(), "islenmis ogeler tekrar gelmemeli");
        // Ortadan devam — atlama olmamalı.
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
            // Baytlar TURA GÖRE farklı: `deposit` artık birebir aynı
            // kopyayı tekilleştiriyor (bkz. orada) ve gerçek hayatta iki
            // ayrı zarfın ciphertext'i asla aynı olmaz.
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
        // Bir ratchet kutusunu iki taraf da hem yazar hem okur. Filtre
        // olmasa herkes kendi giden trafigini geri indirir ve cozemez.
        let s = Store::open_in_memory().unwrap();
        let a = enroll(&s, b"aaaa", "peerA");
        let b = enroll(&s, b"bbbb", "peerB");
        // Bir ratchet kutusunu iki taraf da kaydeder — bkz. `mailbox_readers`.
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
    fn register_needs_a_proof_by_the_key_the_mailbox_is_bound_to() {
        let s = Store::open_in_memory().unwrap();
        let owner = enroll(&s, b"aaaa", "peerA");
        let squatter = enroll(&s, b"bbbb", "peerB");
        let id = vec!["mb_1".to_string()];
        let proof = |key: &[u8]| vec![("mb_1".to_string(), key.to_vec())];
        // No proof: not registered, reported as unproven.
        assert_eq!(s.register_mailboxes_proved(&owner, &id, &[], &[], 0, 10).unwrap(), (vec![], id.clone()));
        assert!(!s.mailbox_is_registered("mb_1"));
        assert_eq!(s.register_mailboxes_proved(&owner, &id, &[], &proof(b"k1"), 0, 10).unwrap(), (vec![], vec![]));
        // Another key is refused, the bound key is taken (second end of a session).
        assert_eq!(s.register_mailboxes_proved(&squatter, &id, &[], &proof(b"k2"), 0, 10).unwrap(), (id.clone(), vec![]));
        assert_eq!(s.register_mailboxes_proved(&squatter, &id, &[], &proof(b"k1"), 0, 10).unwrap(), (vec![], vec![]));
        // A reader registers again without a proof.
        assert_eq!(s.register_mailboxes_proved(&owner, &id, &[], &[], 1, 10).unwrap(), (vec![], vec![]));
    }

    #[test]
    fn a_mailbox_takes_no_third_reader() {
        let s = Store::open_in_memory().unwrap();
        let a = enroll(&s, b"aaaa", "peerA");
        let b = enroll(&s, b"bbbb", "peerB");
        let c = enroll(&s, b"cccc", "peerC");
        register(&s, &a, "mb_1");
        register(&s, &b, "mb_1");
        register(&s, &a, "mb_1");
        assert_eq!(s.register_mailboxes(&c, &["mb_1".to_string()], &[], 0, 100).unwrap().len(), 1);
    }

    #[test]
    fn depositor_cannot_delete_its_own_message() {
        // Aksi halde gonderen, alici hic gormeden mesaji sunucudan silebilirdi.
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
            // bkz. `fetch_respects_byte_and_item_caps` aynı notu — yatırma
            // birebir aynı baytları tekilleştirdiği için her tur farklı.
            last = s.deposit("mb_1", &[b'x', i as u8], &sender, i, 1000).unwrap();
        }
        assert_eq!(s.ack("mb_1", last, &recipient).unwrap(), 5);
        // Tekrar ack: hata degil, sadece 0 satir.
        assert_eq!(s.ack("mb_1", last, &recipient).unwrap(), 0);
    }

    /// bkz. `Store::deposit` — istemcideki tekilleştirme boşluğu yüzünden
    /// aynı el sıkışma saniyede bir yeniden yatırılıyor ve bırakanın kotasını
    /// dolduruyordu. Sunucu artık birebir aynı kopyayı ikinci kez saklamaz.
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

        // Kota da sadece BİR kopya kadar artmış olmalı — asıl çöküş buydu.
        let e = s.enrollment_by_peer("peerS").unwrap();
        assert_eq!(e.bytes_mail as usize, b"ayni-el-sikisma".len());

        // Farklı baytlar hâlâ ayrı satır.
        s.deposit("mb_1", b"baska-zarf", &sender, 60, 1000).unwrap();
        assert_eq!(s.mailbox_item_count("mb_1"), 2);
    }

    /// Defter #03: kutuyu KAYDETMEMİŞ bir istemci ne okuyabilmeli ne de
    /// silebilmeli. Kutu kimliği (ilk-temas kutusu için) tahmin
    /// edilebilir olduğundan, erişim kontrolü olmadan kayıtlı herhangi
    /// biri başkasının postasını çekebiliyor ve `Ack` ile yok
    /// edebiliyordu.
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

    /// İlk-temas kutusunun kimliği parmak izinden türüyor, yani kayıtlı
    /// herhangi biri kutuya okuyucu olarak kaydolabilir. O okuyucunun `Ack`'i
    /// gerçek alıcının postasını silmemeli ve hiç onaylamaması kutuyu
    /// doldurmamalı.
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

        // Alıcı onaylar; yabancı onaylamamış olsaydı satır TTL'e kadar
        // kalırdı ama kapasiteye sayılmazdı. Burada ikisi de onayladı.
        assert_eq!(s.ack("mb_fp", seq, &victim).unwrap(), 1);
        assert_eq!(s.mailbox_item_count("mb_fp"), 0);

        // Hiç onaylamayan yabancı: satır kalır ama kapasiteye sayılmaz.
        let seq2 = s.deposit("mb_fp", b"handshake-2", &sender, 2, 1000).unwrap();
        // A third reader is refused: two per mailbox (2026-10-07).
        let third = enroll(&s, b"sile", "peerQ");
        assert_eq!(s.register_mailboxes(&third, &["mb_fp".to_string()], &[], 0, 100).unwrap().len(), 1);
        // The lurker is the silent reader here: it has not acked seq2.
        assert_eq!(s.ack("mb_fp", seq2, &victim).unwrap(), 0, "sessiz okuyucu varken silinmez");
        assert_eq!(s.mailbox_item_count("mb_fp"), 0, "alicinin onayladigi satir kapasiteye sayilmaz");
        assert_eq!(s.ack("mb_fp", seq2, &lurker).unwrap(), 1);
    }

    /// Eski sürümde yeniden kayıt yeni bir `enrollment_id` açıp eski okuyucu
    /// satırlarını sahipsiz bırakıyordu; o sahip onaylayamaz, postayı TTL'e
    /// kadar tutmamalı.
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

    /// Bir ratchet kutusunun İKİ kayıtlı okuyucusu olur ve biri
    /// diğerinin kaydını EZMEZ (tek-sahipli model bunu kırıyordu).
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

    /// Defter #06: parça adımı blob'la birlikte saklanmalı, yoksa
    /// `serve_chunk` yanlış ofsetlerden okur.
    #[test]
    fn blob_remembers_the_chunk_stride_it_was_written_with() {
        let s = Store::open_in_memory().unwrap();
        let a = enroll(&s, b"aaaa", "peerA");
        s.blob_begin("bl_s", &a, 2, 0).unwrap();
        assert_eq!(s.blob_state("bl_s").unwrap().chunk_size, 0, "baslangicta bilinmiyor");
        s.blob_set_chunk_size("bl_s", 512 * 1024);
        assert_eq!(s.blob_state("bl_s").unwrap().chunk_size, 512 * 1024);
        // Ilk deger SABITLENIR — sonraki parcalar farkli bir adim iddia edemez.
        s.blob_set_chunk_size("bl_s", 256 * 1024);
        assert_eq!(s.blob_state("bl_s").unwrap().chunk_size, 512 * 1024);
    }

    /// Defter #23: kayıt başına kotanın üstünde genel bir tavan da olmalı.
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
        // 100 mail + 50 archive + 2 for the record id "m1" + 25 blob.
        assert_eq!(s.total_stored_bytes(), 177);
    }

    /// Dış inceleme önerisi: gönderen KENDİ teslim edilmemiş paketini geri
    /// çekebilmeli — ama yalnızca kendisininkini.
    #[test]
    fn sender_can_cancel_only_its_own_undelivered_deposit() {
        let s = Store::open_in_memory().unwrap();
        let sender = enroll(&s, b"send", "peerS");
        let other = enroll(&s, b"othr", "peerO");
        let recipient = enroll(&s, b"recv", "peerR");
        register(&s, &recipient, "mb_1");
        let mine = s.deposit("mb_1", b"benim", &sender, 1, 1000).unwrap();
        let theirs = s.deposit("mb_1", b"baskasinin", &other, 2, 1000).unwrap();

        // Baskasinin paketini silemem.
        assert_eq!(s.cancel_own_deposits("mb_1", &[theirs], &sender), 0);
        assert_eq!(s.mailbox_item_count("mb_1"), 2);
        // Kendiminkini geri cekebilirim.
        assert_eq!(s.cancel_own_deposits("mb_1", &[mine], &sender), 1);
        assert_eq!(s.mailbox_item_count("mb_1"), 1);
        // Alici hala digerini gorur.
        let (left, _) = s.fetch(&recipient, &[("mb_1".into(), 0)], 10, 4096);
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].sealed, b"baskasinin");
    }

    /// Kullanıcı kararı: ENGEL, iptalden farklı — anahtar engellenirse taze
    /// bir davet de işe yaramamalı.
    #[test]
    fn blocking_is_keyed_on_the_enrollment_key_not_the_row() {
        let s = Store::open_in_memory().unwrap();
        let key = vec![9u8; 32];
        assert!(!s.is_key_blocked(&key));
        s.block_enrollment_key(&key, 0).unwrap();
        assert!(s.is_key_blocked(&key));
        // Baska bir anahtar etkilenmez.
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
    fn archive_higher_rev_supersedes_lower() {
        let s = Store::open_in_memory().unwrap();
        let a = enroll(&s, b"aaaa", "peerA");
        s.archive_put("ar_1", &[rec("m1", 1, 100, b"ilk")], &a, 0).unwrap();
        s.archive_put("ar_1", &[rec("m1", 2, 100, b"duzeltilmis")], &a, 0).unwrap();
        let (page, _) = s.archive_fetch("ar_1", None, 10, 65536);
        assert_eq!(page.len(), 1, "ayni record_id tek satir olmali");
        assert_eq!(page[0].sealed, b"duzeltilmis");

        // Daha DUSUK bir rev eskiyi geri getirmemeli (sirasiz teslim).
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
        // Sayfalama: son gorulenden eskiye.
        let (older, _) = s.archive_fetch("ar_1", Some(page[1].sent_at_ms), 10, 65536);
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
        // Süre yine de bağlar: sınırsız DEMEK süresiz DEMEK değil.
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
        // Make the insert fail: no table to write to.
        s.conn.execute_batch("ALTER TABLE enrollments RENAME TO gone").unwrap();
        assert!(s.enroll_with_invite(b"h", 1, &e).is_err());
        s.conn.execute_batch("ALTER TABLE gone RENAME TO enrollments").unwrap();
        assert_eq!(s.invite_uses_left(b"h", 0), Some(1), "the use came back with the rollback");
        assert!(s.enroll_with_invite(b"h", 1, &e).unwrap());
        assert!(!s.enroll_with_invite(b"h", 1, &e).unwrap(), "spent");
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
    fn archive_paging_never_splits_a_timestamp_and_never_stalls() {
        let s = Store::open_in_memory().unwrap();
        let a = enroll(&s, b"aaaa", "peerA");
        s.archive_put("ar_1", &[rec("m1", 1, 100, b"a"), rec("m2", 1, 200, b"b"), rec("m3", 1, 200, b"c"), rec("m4", 1, 300, b"d")], &a, 0).unwrap();
        // Walk the bucket two at a time, the way the client does.
        let mut seen = Vec::new();
        let mut before = None;
        loop {
            let (page, more) = s.archive_fetch("ar_1", before, 2, 65536);
            before = page.iter().map(|r| r.sent_at_ms).min();
            seen.extend(page.into_iter().map(|r| r.record_id));
            if !more {
                break;
            }
        }
        seen.sort();
        assert_eq!(seen, ["m1", "m2", "m3", "m4"], "the two records at ts=200 share a page");
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
        assert_eq!(s.enrollment_by_id(&b).unwrap().bytes_archive, 1002, "sealed + record_id");
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
        // Zaten kayitli olani tekrar kaydetmek kotaya takilmamali.
        assert!(s.register_mailboxes(&a, &["mb_1".into()], &[], 1, 2).unwrap().is_empty());
        s.register_mailboxes(&a, &[], &["mb_1".into()], 1, 2).unwrap();
        assert!(!s.mailbox_is_registered("mb_1"));
    }

    #[test]
    fn mail_bytes_are_recounted_after_delivery() {
        // Kota tek yonlu artsaydi aktif bir kullanici birkac ayda kilitlenirdi.
        let s = Store::open_in_memory().unwrap();
        let sender = enroll(&s, b"send", "peerS");
        let recipient = enroll(&s, b"recv", "peerR");
        register(&s, &recipient, "mb_1");
        let seq = s.deposit("mb_1", &vec![b'x'; 500], &sender, 1, 1000).unwrap();
        assert_eq!(s.enrollment_by_peer("peerS").unwrap().bytes_mail, 500);
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
        s.blob_finish("bl_1", b"hash", 5).unwrap();
        assert!(!s.blob_state("bl_1").unwrap().complete, "eksik yukleme servis edilemez");
        s.blob_record_chunk("bl_1", 2, 10).unwrap();
        s.blob_finish("bl_1", b"hash", 5).unwrap();
        assert!(s.blob_state("bl_1").unwrap().complete);
    }

    #[test]
    fn out_of_order_chunks_are_accepted_and_counted() {
        // Boru hattinda parcalar sirasiz gelir; sunucu bunu kabul etmeli ve
        // hepsi gelene kadar 'complete' dememeli.
        let s = Store::open_in_memory().unwrap();
        let a = enroll(&s, b"aaaa", "peerA");
        s.blob_begin("bl_1", &a, 3, 0).unwrap();
        s.blob_record_chunk("bl_1", 2, 10).unwrap();
        s.blob_record_chunk("bl_1", 0, 10).unwrap();
        s.blob_finish("bl_1", b"h", 5).unwrap();
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
        s.blob_record_chunk("bl_1", 0, 100).unwrap(); // baglanti koptu, tekrar
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
        // Indirilmeye devam eden bir dosya yasamaya devam etmeli.
        s.blob_touch("bl_1", 900);
        assert!(s.blobs_to_gc(1500, 1000).is_empty());
        assert_eq!(s.blobs_to_gc(2000, 1000), vec!["bl_1".to_string()]);
    }
}
