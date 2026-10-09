//! Shared whiteboard: one board per 1:1 chat or group.
//!
//! What is stored is a set of strokes per page plus the ids of erased strokes
//! (tombstones), so merging two copies of a page is "union of the strokes,
//! minus everything either side erased" and gives the same result in any
//! order.
//!
//! Traffic is built around the fact that one ratchet packet costs ~8 KB on the
//! wire while a stroke is ~100 bytes: the cost is packets, not points.
//!   * `WbOps`: strokes drawn/erased, batched per burst, sent once and never
//!     retried (an offline device finds them on the store-and-forward server).
//!   * `WbDigest`: sent once a burst has settled, reliable, at most one pending
//!     per board and device. It is the only packet an offline device gets for
//!     a whole drawing session; whoever sees a page differ pulls that page
//!     (`WbPageRequest` / `WbPage`).
//!
//! Every size is capped, both for what is drawn here and for what arrives, so
//! a board cannot grow past `MAX_PAGES * MAX_PAGE_BYTES`.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use log::warn;
use rand::rngs::OsRng;
use rand::RngCore;
use rusqlite::params;

use crate::packet::{MessageContent, WbPageDigest, WbStroke};
use crate::{current_time_ms, P2PCore, STALE_PEER_RETRY_HORIZON_MS};

/// Virtual canvas, 16:10. Every device scales this to its own screen.
pub const WIDTH: u16 = 1600;
pub const HEIGHT: u16 = 1000;
pub const MAX_PAGES: u8 = 20;
pub const MAX_STROKE_POINTS: usize = 512;
/// Stored stroke bytes per page; a full page refuses new strokes.
pub const MAX_PAGE_BYTES: usize = 48 * 1024;
pub const MAX_OPS_STROKES: usize = 64;
pub const MAX_PEN_WIDTH: u8 = 40;
// ponytail: tombstones are capped; dropped first are those for strokes this
// device never held (a peer can make up any number of those), then the oldest.
// A device that stays offline through more than this many erases on one page
// can bring an erased stroke back. Add a per-page epoch (clear = epoch + 1) if
// that ever shows up.
pub const MAX_TOMBSTONES: usize = 2048;

/// Pen has been up this long: the burst is over, send it.
const OPS_DEBOUNCE_MS: u64 = 800;
/// Nobody waits longer than this for a stroke while drawing continues.
const OPS_MAX_DELAY_MS: u64 = 3_000;
const DIGEST_DELAY_MS: u64 = 5_000;
// ponytail: two full pages with different strokes can never become equal, so
// answering a page with a digest is rate limited instead of tracked per round.
const DIGEST_REPLY_MIN_MS: u64 = 30_000;
/// Budget for what one device may make us send on one board: a whole board
/// (`MAX_PAGES` pages, or as many digests) at once, then one per this long.
/// A page answer is ~64 KB sent for an ~8 KB request.
const PULL_COST_MS: u64 = 15_000;

pub(crate) const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS wb_strokes (
        board TEXT NOT NULL,
        page INTEGER NOT NULL,
        stroke_id BLOB NOT NULL,
        author TEXT NOT NULL,
        shade INTEGER NOT NULL,
        points BLOB NOT NULL,
        width INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (board, stroke_id)
    );
    CREATE INDEX IF NOT EXISTS wb_strokes_page ON wb_strokes (board, page);
    CREATE TABLE IF NOT EXISTS wb_tombstones (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        board TEXT NOT NULL,
        page INTEGER NOT NULL,
        stroke_id BLOB NOT NULL,
        seen INTEGER NOT NULL DEFAULT 1,
        UNIQUE (board, stroke_id)
    );
";

/// Strokes and erases not sent yet, and when the settling digest is due.
pub(crate) struct WbOutbox {
    group_id: Option<String>,
    conversation_identity_id: Option<String>,
    strokes: Vec<WbStroke>,
    erased: Vec<u8>,
    first_at: u64,
    last_at: u64,
    digest_at: u64,
}

struct Board {
    /// `g:<group id>` or `d:<contact identity id>`.
    key: String,
    group_id: Option<String>,
    conversation_identity_id: Option<String>,
}

/// The trust-boundary check: applied to strokes drawn here and to every stroke
/// that arrives.
pub fn stroke_ok(s: &WbStroke) -> bool {
    s.id.len() == 8
        && s.page < MAX_PAGES
        && s.shade < 3
        && s.width <= MAX_PEN_WIDTH
        && !s.points.is_empty()
        && s.points.len() % 4 == 0
        && s.points.len() <= MAX_STROKE_POINTS * 4
        && s.points.chunks_exact(4).all(|p| {
            u16::from_le_bytes([p[0], p[1]]) <= WIDTH && u16::from_le_bytes([p[2], p[3]]) <= HEIGHT
        })
}

fn id_u64(id: &[u8]) -> u64 {
    id.try_into().map(u64::from_le_bytes).unwrap_or(0)
}

fn noop() -> serde_json::Value {
    serde_json::json!({"type": "noop"})
}

// ------------------------------------------------------------------ storage

impl P2PCore {
    /// Stroke points are user content: sealed at rest like queued messages.
    fn wb_seal(&self, points: &[u8]) -> Vec<u8> {
        self.seal_local_blob(points).unwrap_or_else(|| points.to_vec())
    }

    fn wb_unseal(&self, stored: Vec<u8>) -> Vec<u8> {
        self.open_local_blob(&stored).unwrap_or(stored)
    }

    fn wb_is_tombstoned(&self, board: &str, id: &[u8]) -> bool {
        self.db.as_ref().map_or(false, |conn| {
            conn.query_row(
                "SELECT 1 FROM wb_tombstones WHERE board = ?1 AND stroke_id = ?2",
                params![board, id],
                |_| Ok(()),
            )
            .is_ok()
        })
    }

    /// Adds a stroke unless it is invalid, already here, erased, or the page
    /// is full. `true` = the page changed.
    #[cfg(test)]
    fn wb_insert(&self, board: &str, stroke: &WbStroke, author: &str) -> bool {
        let mut used = self.wb_page_used(board, stroke.page);
        self.wb_insert_counted(board, stroke, author, &mut used)
    }

    /// Stored stroke bytes of a page. `LENGTH` of the sealed blob, as before.
    fn wb_page_used(&self, board: &str, page: u8) -> usize {
        self.db.as_ref().map_or(0, |conn| {
            conn.query_row(
                "SELECT COALESCE(SUM(LENGTH(points)), 0) FROM wb_strokes WHERE board = ?1 AND page = ?2",
                params![board, page],
                |r| r.get::<_, i64>(0),
            )
            .unwrap_or(0) as usize
        })
    }

    /// `wb_insert` for many strokes of one page: `used` is that page's
    /// `wb_page_used`, kept current here, so a whole page costs one SUM.
    fn wb_insert_counted(&self, board: &str, stroke: &WbStroke, author: &str, used: &mut usize) -> bool {
        let Some(conn) = &self.db else { return false };
        if !stroke_ok(stroke) || self.wb_is_tombstoned(board, &stroke.id) {
            return false;
        }
        if *used + stroke.points.len() > MAX_PAGE_BYTES {
            return false;
        }
        let sealed = self.wb_seal(&stroke.points);
        let added = sealed.len();
        let inserted = conn
            .execute(
                "INSERT OR IGNORE INTO wb_strokes (board, page, stroke_id, author, shade, points, width) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![board, stroke.page, stroke.id, author, stroke.shade, sealed, stroke.width],
            )
            .map_or(false, |n| n > 0);
        if inserted {
            *used += added;
        }
        inserted
    }

    /// One transaction around a packet's worth of statements: a peer can send
    /// thousands, and each autocommit is a sync under the core lock.
    fn wb_tx(&self) -> Option<rusqlite::Transaction<'_>> {
        self.db.as_ref().and_then(|conn| conn.unchecked_transaction().ok())
    }

    /// Enforces `MAX_TOMBSTONES` per page. Once per packet, not per erase.
    fn wb_trim_tombstones(&self, board: &str) {
        let Some(conn) = &self.db else { return };
        let _ = conn.execute(
            "DELETE FROM wb_tombstones WHERE seq IN (
                SELECT seq FROM (
                    SELECT seq, ROW_NUMBER() OVER (PARTITION BY page ORDER BY seen DESC, seq DESC) AS n
                    FROM wb_tombstones WHERE board = ?1)
                WHERE n > ?2)",
            params![board, MAX_TOMBSTONES as i64],
        );
    }

    /// Token bucket (as a virtual clock in `wb_reply_at`) for what `peer_fp`
    /// may make us send on a board. `false` = over budget, drop the request.
    fn wb_pull_allowed(&mut self, kind: &str, board: &str, peer_fp: &str, units: u64) -> bool {
        let now = current_time_ms();
        let slot = (format!("{}#{}", board, kind), peer_fp.to_string());
        let due = self.wb_reply_at.get(&slot).copied().unwrap_or(0).max(now) + units * PULL_COST_MS;
        if due - now > MAX_PAGES as u64 * PULL_COST_MS {
            warn!("Whiteboard {} from {} dropped: over budget", kind, &peer_fp[..peer_fp.len().min(8)]);
            return false;
        }
        self.wb_reply_at.insert(slot, due);
        true
    }

    /// Erases a stroke and remembers its id so a late copy cannot come back.
    /// Returns the page of the stroke if it was here. The caller runs
    /// `wb_trim_tombstones` when it is done.
    fn wb_erase(&self, board: &str, hint_page: u8, id: &[u8]) -> Option<u8> {
        let conn = self.db.as_ref()?;
        if id.len() != 8 || hint_page >= MAX_PAGES {
            return None;
        }
        let live: Option<u8> = conn
            .query_row(
                "SELECT page FROM wb_strokes WHERE board = ?1 AND stroke_id = ?2",
                params![board, id],
                |r| r.get(0),
            )
            .ok();
        let page = live.unwrap_or(hint_page);
        let _ = conn.execute("DELETE FROM wb_strokes WHERE board = ?1 AND stroke_id = ?2", params![board, id]);
        let _ = conn.execute(
            "INSERT OR IGNORE INTO wb_tombstones (board, page, stroke_id, seen) VALUES (?1, ?2, ?3, ?4)",
            params![board, page, id, live.is_some()],
        );
        live
    }

    /// Pages that hold strokes: stroke count and XOR of the stroke ids.
    fn wb_digest(&self, board: &str) -> Vec<WbPageDigest> {
        let mut pages: BTreeMap<u8, (u32, u64)> = BTreeMap::new();
        if let Some(conn) = &self.db {
            if let Ok(mut stmt) = conn.prepare("SELECT page, stroke_id FROM wb_strokes WHERE board = ?1") {
                if let Ok(rows) = stmt.query_map(params![board], |r| Ok((r.get::<_, u8>(0)?, r.get::<_, Vec<u8>>(1)?))) {
                    for (page, id) in rows.flatten() {
                        let entry = pages.entry(page).or_insert((0, 0));
                        entry.0 += 1;
                        entry.1 ^= id_u64(&id);
                    }
                }
            }
        }
        pages.into_iter().map(|(page, (count, hash))| WbPageDigest { page, count, hash }).collect()
    }

    /// Strokes of one page with their author, in drawing order.
    fn wb_page_strokes(&self, board: &str, page: u8) -> Vec<(WbStroke, String)> {
        let mut out = Vec::new();
        if let Some(conn) = &self.db {
            if let Ok(mut stmt) = conn.prepare(
                "SELECT stroke_id, shade, points, author, width FROM wb_strokes WHERE board = ?1 AND page = ?2 ORDER BY rowid",
            ) {
                let rows = stmt.query_map(params![board, page], |r| {
                    Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, u8>(1)?, r.get::<_, Vec<u8>>(2)?, r.get::<_, String>(3)?, r.get::<_, u8>(4)?))
                });
                if let Ok(rows) = rows {
                    for (id, shade, points, author, width) in rows.flatten() {
                        out.push((WbStroke { id, page, shade, author: 0, width, points: self.wb_unseal(points) }, author));
                    }
                }
            }
        }
        out
    }

    fn wb_page_tombstones(&self, board: &str, page: u8) -> Vec<u8> {
        let mut out = Vec::new();
        if let Some(conn) = &self.db {
            if let Ok(mut stmt) = conn.prepare("SELECT stroke_id FROM wb_tombstones WHERE board = ?1 AND page = ?2") {
                if let Ok(rows) = stmt.query_map(params![board, page], |r| r.get::<_, Vec<u8>>(0)) {
                    for id in rows.flatten() {
                        out.extend_from_slice(&id);
                    }
                }
            }
        }
        out
    }

    /// Bit per page that someone else changed and nobody looked at here yet.
    fn wb_unread(&self, board: &str) -> u32 {
        self.db.as_ref().map_or(0, |conn| {
            conn.query_row("SELECT v FROM app_meta WHERE k = ?1", params![format!("wb_unread:{}", board)], |r| r.get::<_, i64>(0))
                .unwrap_or(0) as u32
        })
    }

    fn wb_set_unread(&self, board: &str, mask: u32) {
        let Some(conn) = &self.db else { return };
        let key = format!("wb_unread:{}", board);
        let _ = if mask == 0 {
            conn.execute("DELETE FROM app_meta WHERE k = ?1", params![key])
        } else {
            conn.execute("INSERT OR REPLACE INTO app_meta (k, v) VALUES (?1, ?2)", params![key, mask as i64])
        };
    }

    /// Removes a board for good: its chat was cleared or no longer exists.
    pub(crate) fn wb_delete_board(&mut self, group_id: Option<&str>, identity_id: Option<&str>) {
        let key = match (group_id, identity_id) {
            (Some(gid), _) => format!("g:{}", gid),
            (None, Some(id)) => format!("d:{}", id),
            (None, None) => return,
        };
        if let Some(conn) = &self.db {
            let _ = conn.execute("DELETE FROM wb_strokes WHERE board = ?1", params![key]);
            let _ = conn.execute("DELETE FROM wb_tombstones WHERE board = ?1", params![key]);
        }
        self.wb_set_unread(&key, 0);
        self.wb_outbox.remove(&key);
        self.wb_reply_at.retain(|(board, _), _| board.split('#').next() != Some(key.as_str()));
    }
}

// ------------------------------------------------------------------ sending

impl P2PCore {
    /// The board of the chat a UI call names: `group_id`, or the 1:1 chat with
    /// the owner of `peer_fp` when `group_id` is empty.
    fn wb_board(&self, peer_fp: &str, group_id: &str) -> Result<Board, String> {
        if !group_id.is_empty() {
            if !self.groups.contains_key(group_id) {
                return Err("Unknown group".to_string());
            }
            return Ok(Board { key: format!("g:{}", group_id), group_id: Some(group_id.to_string()), conversation_identity_id: None });
        }
        let identity_id = self.known_remote_devices.get(peer_fp).map(|d| d.identity_id.clone()).ok_or("Unknown peer")?;
        Ok(Board { key: format!("d:{}", identity_id), group_id: None, conversation_identity_id: Some(identity_id) })
    }

    /// Everyone who draws on the board, sorted by identity id. The order is
    /// the same on every device, and it is what the colours are derived from.
    fn wb_participants(&self, board: &Board) -> Vec<String> {
        let mut ids = match (&board.group_id, &board.conversation_identity_id) {
            (Some(gid), _) => self.groups.get(gid).map(|g| g.member_identity_ids()).unwrap_or_default(),
            (None, Some(id)) => vec![id.clone()],
            (None, None) => Vec::new(),
        };
        ids.extend(self.my_identity_id());
        ids.sort();
        ids.dedup();
        ids
    }

    /// Every device that shows this board: the participants' devices and my
    /// own other devices. A device unseen for a week is left out, like
    /// `sibling_active_devices` does.
    fn wb_targets(&self, board: &Board) -> Vec<String> {
        let participants = self.wb_participants(board);
        let own_fp = self.get_active_own_device_fingerprint().ok();
        let now = current_time_ms();
        let mut targets: Vec<String> = self.known_remote_devices.values()
            .filter(|d| d.is_active && participants.contains(&d.identity_id))
            .filter(|d| !self.deleted_identities.contains(&d.identity_id))
            // Only over an established session: a whiteboard packet must never
            // start a handshake of its own (it raced the chat screen's and the
            // two sessions diverged — two-device test, 2026-10-01).
            .filter(|d| self.ratchets.contains_key(&d.device_fingerprint))
            .filter(|d| now.saturating_sub(d.last_seen) < STALE_PEER_RETRY_HORIZON_MS)
            .map(|d| d.device_fingerprint.clone())
            .filter(|fp| own_fp.as_deref() != Some(fp.as_str()))
            .collect();
        targets.sort();
        targets.dedup();
        targets
    }

    fn wb_queue(&mut self, board: &Board) -> &mut WbOutbox {
        let now = current_time_ms();
        let outbox = self.wb_outbox.entry(board.key.clone()).or_insert_with(|| WbOutbox {
            group_id: board.group_id.clone(),
            conversation_identity_id: board.conversation_identity_id.clone(),
            strokes: Vec::new(),
            erased: Vec::new(),
            first_at: now,
            last_at: now,
            digest_at: 0,
        });
        if outbox.strokes.is_empty() && outbox.erased.is_empty() {
            outbox.first_at = now;
        }
        outbox.last_at = now;
        outbox.digest_at = now + DIGEST_DELAY_MS;
        outbox
    }

    /// Sends the queued strokes/erases as one packet per device.
    fn wb_flush_ops(&mut self, key: &str) {
        let Some(outbox) = self.wb_outbox.get_mut(key) else { return };
        if outbox.strokes.is_empty() && outbox.erased.is_empty() {
            return;
        }
        let board = Board {
            key: key.to_string(),
            group_id: outbox.group_id.clone(),
            conversation_identity_id: outbox.conversation_identity_id.clone(),
        };
        let content = MessageContent::WbOps {
            group_id: board.group_id.clone(),
            conversation_identity_id: board.conversation_identity_id.clone(),
            strokes: std::mem::take(&mut outbox.strokes),
            erased: std::mem::take(&mut outbox.erased),
        };
        // Offline devices included (user decision, 2026-10-01): the packet is
        // then left on the store-and-forward server, one deposit per burst.
        for fp in self.wb_targets(&board) {
            if let Err(e) = self.send_message_content(fp, &content, None) {
                warn!("Whiteboard ops not sent: {}", e);
            }
        }
    }

    /// Reliable, but only the newest digest of a board stays queued per
    /// device (same idea as `sync_read_state`).
    fn wb_send_digest(&mut self, board: &Board, targets: Vec<String>) {
        let content = MessageContent::WbDigest {
            group_id: board.group_id.clone(),
            conversation_identity_id: board.conversation_identity_id.clone(),
            pages: self.wb_digest(&board.key),
        };
        let stale: Vec<String> = self.awaiting_confirmation.iter()
            .filter(|(_, p)| targets.contains(&p.peer_device_fingerprint))
            .filter(|(_, p)| matches!(
                &p.regen_content,
                Some(MessageContent::WbDigest { group_id: g, conversation_identity_id: c, .. })
                    if *g == board.group_id && *c == board.conversation_identity_id
            ))
            .map(|(id, _)| id.clone())
            .collect();
        for id in stale {
            self.awaiting_confirmation.remove(&id);
            self.remove_durable_retry(&id);
        }
        for fp in targets {
            if let Err(e) = self.send_message_content(fp, &content, None) {
                warn!("Whiteboard digest not sent: {}", e);
            }
        }
    }

    /// Runs the two timers. Called from the poll loop and from the UI's own
    /// pen-up timer (`wb_tick`), so it does not depend on the poll cadence.
    pub(crate) fn wb_sweep(&mut self) {
        if self.wb_outbox.is_empty() {
            return;
        }
        let now = current_time_ms();
        let keys: Vec<String> = self.wb_outbox.keys().cloned().collect();
        for key in keys {
            let Some(outbox) = self.wb_outbox.get(&key) else { continue };
            let has_ops = !outbox.strokes.is_empty() || !outbox.erased.is_empty();
            if has_ops {
                if now.saturating_sub(outbox.last_at) >= OPS_DEBOUNCE_MS || now.saturating_sub(outbox.first_at) >= OPS_MAX_DELAY_MS {
                    self.wb_flush_ops(&key);
                }
            } else if now >= outbox.digest_at {
                let Some(outbox) = self.wb_outbox.remove(&key) else { continue };
                let board = Board { key, group_id: outbox.group_id, conversation_identity_id: outbox.conversation_identity_id };
                let targets = self.wb_targets(&board);
                self.wb_send_digest(&board, targets);
            }
        }
    }

    /// A stroke drawn on this device. `points`: little-endian u16 x,y pairs.
    /// A stroke longer than `MAX_STROKE_POINTS` is stored as several strokes
    /// that share their end points. Returns the stroke ids as hex (16 digits
    /// each), which is what the UI needs to undo the stroke.
    pub(crate) fn wb_add_stroke(&mut self, peer_fp: &str, group_id: &str, page: u8, shade: u8, width: u8, points: &[u8]) -> Result<String, String> {
        let board = self.wb_board(peer_fp, group_id)?;
        let me = self.my_identity_id().ok_or("No identity")?;
        if points.is_empty() || points.len() % 4 != 0 {
            return Err("Invalid stroke".to_string());
        }
        let step = (MAX_STROKE_POINTS - 1) * 4;
        let mut start = 0;
        let mut segments = Vec::new();
        loop {
            let end = (start + MAX_STROKE_POINTS * 4).min(points.len());
            let mut id = vec![0u8; 8];
            OsRng.fill_bytes(&mut id);
            let stroke = WbStroke { id, page, shade, author: 0, width, points: points[start..end].to_vec() };
            if !stroke_ok(&stroke) {
                return Err("Invalid stroke".to_string());
            }
            segments.push(stroke);
            if end == points.len() {
                break;
            }
            start += step;
        }
        // All segments or none: the UI gets no ids on an error, so a stroke
        // stored in part could be neither shown nor undone, yet went to peers.
        let mut used = self.wb_page_used(&board.key, page);
        let sealing = self.wb_seal(&[]).len(); // what `wb_seal` adds per stroke
        if used + segments.iter().map(|s| s.points.len() + sealing).sum::<usize>() > MAX_PAGE_BYTES {
            return Err("Page full".to_string());
        }
        let mut ids = String::new();
        for stroke in segments {
            if !self.wb_insert_counted(&board.key, &stroke, &me, &mut used) {
                continue; // database error only: the checks above passed
            }
            ids.push_str(&hex::encode(&stroke.id));
            // The receiver drops a whole packet over `MAX_OPS_STROKES`.
            if self.wb_outbox.get(&board.key).map_or(false, |o| o.strokes.len() >= MAX_OPS_STROKES) {
                self.wb_flush_ops(&board.key);
            }
            self.wb_queue(&board).strokes.push(stroke);
        }
        // Continuous drawing never reaches the debounce; this enforces the maximum delay.
        self.wb_sweep();
        // Nothing stored (database error): an error, not an empty success.
        // The screen took "" for a stroke without id and reloaded the page,
        // so the stroke vanished without a word.
        if ids.is_empty() {
            return Err("Stroke not stored".to_string());
        }
        Ok(ids)
    }

    /// Strokes erased on this device. `ids`: 8 bytes per stroke.
    pub(crate) fn wb_erase_strokes(&mut self, peer_fp: &str, group_id: &str, ids: &[u8]) -> Result<(), String> {
        let board = self.wb_board(peer_fp, group_id)?;
        for id in ids.chunks_exact(8) {
            let Some(page) = self.wb_erase(&board.key, 0, id) else { continue };
            // The receiver drops a whole packet over this many erase records.
            if self.wb_outbox.get(&board.key).map_or(false, |o| o.erased.len() >= MAX_TOMBSTONES * 9) {
                self.wb_flush_ops(&board.key);
            }
            let outbox = self.wb_queue(&board);
            // Drawn and erased within one burst: nobody else has it.
            if let Some(at) = outbox.strokes.iter().position(|s| s.id == id) {
                outbox.strokes.remove(at);
            } else {
                outbox.erased.push(page);
                outbox.erased.extend_from_slice(id);
            }
        }
        self.wb_trim_tombstones(&board.key);
        self.wb_sweep();
        Ok(())
    }

    /// The board panel was opened: tell connected devices what this device
    /// has, so anything missed on either side is pulled now.
    pub(crate) fn wb_open(&mut self, peer_fp: &str, group_id: &str) -> Result<(), String> {
        let board = self.wb_board(peer_fp, group_id)?;
        let targets: Vec<String> = self.wb_targets(&board).into_iter().filter(|fp| self.is_connected_to_device(fp)).collect();
        self.wb_send_digest(&board, targets);
        Ok(())
    }

    pub(crate) fn wb_mark_read(&mut self, peer_fp: &str, group_id: &str, page: u8) -> Result<(), String> {
        let board = self.wb_board(peer_fp, group_id)?;
        if page < MAX_PAGES {
            let mask = self.wb_unread(&board.key);
            self.wb_set_unread(&board.key, mask & !(1u32 << page));
        }
        Ok(())
    }

    /// `{"pages", "unread", "me", "participants": [{"id", "name"}]}` —
    /// `pages` is the number of pages in use, `unread` a bit per page, `me`
    /// this account's index in `participants` (the colour order).
    pub(crate) fn wb_info(&self, peer_fp: &str, group_id: &str) -> Result<String, String> {
        let board = self.wb_board(peer_fp, group_id)?;
        let me = self.my_identity_id().unwrap_or_default();
        let participants = self.wb_participants(&board);
        let names: Vec<serde_json::Value> = participants.iter().map(|id| {
            let name = if *id == me {
                self.own_display_name()
            } else {
                self.identity_to_contact.get(id).and_then(|cid| self.contacts.get(cid)).map(|c| c.display_name.clone())
            };
            serde_json::json!({"id": id, "name": name.unwrap_or_else(|| id.chars().take(8).collect())})
        }).collect();
        let pages = self.wb_digest(&board.key).last().map_or(1, |d| d.page as u32 + 1);
        Ok(serde_json::json!({
            "pages": pages,
            "unread": self.wb_unread(&board.key),
            "me": participants.iter().position(|id| *id == me),
            "participants": names,
        }).to_string())
    }

    /// One page for drawing. Per stroke: id (8), shade (1), author index into
    /// the `wb_info` participants or 255 (1), width (1), point count (u16 LE),
    /// points.
    pub(crate) fn wb_page_blob(&self, peer_fp: &str, group_id: &str, page: u8) -> Vec<u8> {
        let Ok(board) = self.wb_board(peer_fp, group_id) else { return Vec::new() };
        let participants = self.wb_participants(&board);
        let mut out = Vec::new();
        for (stroke, author) in self.wb_page_strokes(&board.key, page) {
            let index = participants.iter().position(|id| *id == author).map_or(255, |i| i.min(254) as u8);
            out.extend_from_slice(&stroke.id);
            out.push(stroke.shade);
            out.push(index);
            out.push(stroke.width);
            out.extend_from_slice(&((stroke.points.len() / 4) as u16).to_le_bytes());
            out.extend_from_slice(&stroke.points);
        }
        out
    }
}

// ---------------------------------------------------------------- receiving

impl P2PCore {
    /// The authorization gate of every incoming whiteboard packet: which board
    /// it is for, who sent it, and whether that was one of my own devices.
    /// `None` = the sender has no business on that board.
    ///
    /// The sender is the identity this device is REGISTERED under, not a field
    /// of the packet. A group board needs a member; a 1:1 board is the
    /// sender's own, and only my own devices may name another one.
    fn wb_incoming_board(&self, peer_fp: &str, group_id: &Option<String>, conversation_identity_id: &Option<String>) -> Option<(Board, String, bool)> {
        let me = self.my_identity_id()?;
        let sender = self.known_remote_devices.get(peer_fp)?.identity_id.clone();
        let from_self = sender == me;
        if let Some(gid) = group_id {
            if !self.groups.get(gid)?.is_member(&sender) {
                warn!("Whiteboard packet rejected: sender is not a member (group={})", gid);
                return None;
            }
            let board = Board { key: format!("g:{}", gid), group_id: Some(gid.clone()), conversation_identity_id: None };
            return Some((board, sender, from_self));
        }
        let identity = if from_self { conversation_identity_id.clone()? } else { sender.clone() };
        if !self.identity_to_contact.contains_key(&identity) || self.is_blocked(&identity) {
            return None;
        }
        let board = Board { key: format!("d:{}", identity), group_id: None, conversation_identity_id: Some(identity) };
        Some((board, sender, from_self))
    }

    /// The UI event for changed pages; marks them unread unless I drew them.
    fn wb_changed(&self, board: &Board, pages: &BTreeSet<u8>, mark_unread: bool) -> serde_json::Value {
        if pages.is_empty() {
            return noop();
        }
        let mut mask = self.wb_unread(&board.key);
        if mark_unread {
            mask = pages.iter().fold(mask, |m, p| m | (1u32 << p));
            self.wb_set_unread(&board.key, mask);
        }
        let pages: Vec<u8> = pages.iter().copied().collect();
        match (&board.group_id, &board.conversation_identity_id) {
            (Some(gid), _) => serde_json::json!({"type": "whiteboard", "group_id": gid, "pages": pages, "unread": mask}),
            (None, Some(id)) => serde_json::json!({
                "type": "whiteboard", "peer": self.canonical_device_for_identity(id).unwrap_or_default(),
                "pages": pages, "unread": mask
            }),
            (None, None) => noop(),
        }
    }

    pub(crate) fn wb_on_ops(&mut self, peer_fp: &str, group_id: Option<String>, conversation_identity_id: Option<String>, strokes: Vec<WbStroke>, erased: Vec<u8>) -> serde_json::Value {
        let Some((board, sender, from_self)) = self.wb_incoming_board(peer_fp, &group_id, &conversation_identity_id) else { return noop() };
        if strokes.len() > MAX_OPS_STROKES || erased.len() % 9 != 0 || erased.len() > MAX_TOMBSTONES * 9 {
            return noop();
        }
        let mut pages = BTreeSet::new();
        let tx = self.wb_tx();
        // One SUM per page of the packet, not one per stroke.
        let mut used: HashMap<u8, usize> = HashMap::new();
        for stroke in &strokes {
            let used = used.entry(stroke.page).or_insert_with(|| self.wb_page_used(&board.key, stroke.page));
            // The author is whoever sent the packet, never a field in it.
            if self.wb_insert_counted(&board.key, stroke, &sender, used) {
                pages.insert(stroke.page);
            }
        }
        for record in erased.chunks_exact(9) {
            if let Some(page) = self.wb_erase(&board.key, record[0], &record[1..]) {
                pages.insert(page);
            }
        }
        if !erased.is_empty() {
            self.wb_trim_tombstones(&board.key);
        }
        let _ = tx.map(|tx| tx.commit());
        self.wb_changed(&board, &pages, !from_self)
    }

    /// Their board summary: pull every page that differs from mine.
    pub(crate) fn wb_on_digest(&mut self, peer_fp: &str, group_id: Option<String>, conversation_identity_id: Option<String>, pages: Vec<WbPageDigest>) -> serde_json::Value {
        let Some((board, _, _)) = self.wb_incoming_board(peer_fp, &group_id, &conversation_identity_id) else { return noop() };
        if pages.len() > MAX_PAGES as usize || !self.wb_pull_allowed("digest", &board.key, peer_fp, 1) {
            return noop();
        }
        // Strokes of mine are still on their way out: the pages differ only
        // by those, and pulling now moved two full pages each time one side
        // paused while both were drawing. My own digest follows the flush.
        if self.wb_outbox.get(&board.key).map_or(false, |o| !o.strokes.is_empty() || !o.erased.is_empty()) {
            return noop();
        }
        let theirs: HashMap<u8, (u32, u64)> = pages.iter().map(|d| (d.page, (d.count, d.hash))).collect();
        let mine: HashMap<u8, (u32, u64)> = self.wb_digest(&board.key).iter().map(|d| (d.page, (d.count, d.hash))).collect();
        let differing: Vec<u8> = (0..MAX_PAGES).filter(|p| mine.get(p) != theirs.get(p)).collect();
        if !differing.is_empty() {
            let request = MessageContent::WbPageRequest {
                group_id: board.group_id.clone(),
                conversation_identity_id: board.conversation_identity_id.clone(),
                pages: differing,
            };
            if let Err(e) = self.send_message_content(peer_fp.to_string(), &request, None) {
                warn!("Whiteboard page request not sent: {}", e);
            }
        }
        noop()
    }

    pub(crate) fn wb_on_page_request(&mut self, peer_fp: &str, group_id: Option<String>, conversation_identity_id: Option<String>, pages: Vec<u8>) -> serde_json::Value {
        let Some((board, _, _)) = self.wb_incoming_board(peer_fp, &group_id, &conversation_identity_id) else { return noop() };
        let pages: BTreeSet<u8> = pages.into_iter().filter(|p| *p < MAX_PAGES).collect();
        if pages.is_empty() || !self.wb_pull_allowed("pages", &board.key, peer_fp, pages.len() as u64) {
            return noop();
        }
        for page in pages {
            let mut authors: Vec<String> = Vec::new();
            let strokes: Vec<WbStroke> = self.wb_page_strokes(&board.key, page).into_iter().filter_map(|(mut stroke, author)| {
                let index = match authors.iter().position(|a| *a == author) {
                    Some(i) => i,
                    None => { authors.push(author); authors.len() - 1 }
                };
                stroke.author = u8::try_from(index).ok()?;
                Some(stroke)
            }).collect();
            let content = MessageContent::WbPage {
                group_id: board.group_id.clone(),
                conversation_identity_id: board.conversation_identity_id.clone(),
                page,
                authors,
                strokes,
                tombstones: self.wb_page_tombstones(&board.key, page),
            };
            if let Err(e) = self.send_message_content(peer_fp.to_string(), &content, None) {
                warn!("Whiteboard page not sent: {}", e);
            }
        }
        noop()
    }

    /// A whole page from another device: merge it into mine. If I then hold
    /// something that device lacks, send my digest so it pulls from me.
    ///
    /// The authors of relayed strokes are the relaying device's claim — the
    /// same trust a group history sync gets. On a 1:1 board only the two of us
    /// can be authors.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn wb_on_page(&mut self, peer_fp: &str, group_id: Option<String>, conversation_identity_id: Option<String>, page: u8, authors: Vec<String>, strokes: Vec<WbStroke>, tombstones: Vec<u8>) -> serde_json::Value {
        let Some((board, _, _)) = self.wb_incoming_board(peer_fp, &group_id, &conversation_identity_id) else { return noop() };
        if page >= MAX_PAGES
            || authors.len() > 256
            || strokes.len() > MAX_PAGE_BYTES / 4
            || tombstones.len() % 8 != 0
            || tombstones.len() > MAX_TOMBSTONES * 8
        {
            return noop();
        }
        let me = self.my_identity_id().unwrap_or_default();
        let participants = self.wb_participants(&board);
        let mut changed = BTreeSet::new();
        let mut foreign = false;
        let tx = self.wb_tx();
        for id in tombstones.chunks_exact(8) {
            // The stroke may live on another page here: that page changed.
            if let Some(live_page) = self.wb_erase(&board.key, page, id) {
                changed.insert(live_page);
                foreign = true;
            }
        }
        if !tombstones.is_empty() {
            self.wb_trim_tombstones(&board.key);
        }
        let mut used = self.wb_page_used(&board.key, page);
        let mut they_lack = false;
        let mut theirs: HashSet<&[u8]> = HashSet::new();
        for stroke in strokes.iter().filter(|s| s.page == page) {
            theirs.insert(stroke.id.as_slice());
            let Some(author) = authors.get(stroke.author as usize) else { continue };
            if author.len() > 128 || (board.group_id.is_none() && !participants.contains(author)) {
                continue;
            }
            if self.wb_insert_counted(&board.key, stroke, author, &mut used) {
                changed.insert(page);
                foreign |= *author != me;
            } else if self.wb_is_tombstoned(&board.key, &stroke.id) {
                they_lack = true; // erased here, still alive there
            }
        }
        they_lack |= self.wb_page_strokes(&board.key, page).iter().any(|(s, _)| !theirs.contains(s.id.as_slice()));
        let _ = tx.map(|tx| tx.commit());
        if they_lack {
            let now = current_time_ms();
            let slot = (board.key.clone(), peer_fp.to_string());
            if now.saturating_sub(self.wb_reply_at.get(&slot).copied().unwrap_or(0)) >= DIGEST_REPLY_MIN_MS {
                self.wb_reply_at.insert(slot, now);
                self.wb_send_digest(&board, vec![peer_fp.to_string()]);
            }
        }
        self.wb_changed(&board, &changed, foreign)
    }
}

// ---------------------------------------------------------------------- JNI

mod jni_exports {
    use jni::objects::{JByteArray, JClass, JString};
    use jni::sys::{jbyteArray, jint, jstring};
    use jni::JNIEnv;

    use crate::{bytes_to_jbytearray, catch_panic, core_lock, jbytearray_to_vec, safe_new_jstring, RUNTIME};

    fn jstr(env: &mut JNIEnv, s: &JString) -> String {
        env.get_string(s).map(|s| s.into()).unwrap_or_default()
    }

    /// "OK" or "Error: ...", like the other `P2PLib` calls.
    fn status(result: Result<Result<(), String>, String>) -> String {
        match result {
            Ok(Ok(())) => "OK".to_string(),
            Ok(Err(e)) | Err(e) => format!("Error: {}", e),
        }
    }

    #[no_mangle]
    pub extern "system" fn Java_com_p2p_messenger_P2PLib_whiteboardAddStroke<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, peer: JString<'local>, group_id: JString<'local>, page: jint, shade: jint, width: jint, points: JByteArray<'local>) -> jstring {
        let (peer, gid) = (jstr(&mut env, &peer), jstr(&mut env, &group_id));
        let points = jbytearray_to_vec(&mut env, &points);
        let result = catch_panic(move || {
            let _guard = RUNTIME.enter();
            core_lock().wb_add_stroke(&peer, &gid, page.clamp(0, 255) as u8, shade.clamp(0, 255) as u8, width.clamp(0, 255) as u8, &points)
        });
        let out = match result {
            Ok(Ok(ids)) => ids,
            Ok(Err(e)) | Err(e) => format!("Error: {}", e),
        };
        safe_new_jstring(&mut env, out)
    }

    #[no_mangle]
    pub extern "system" fn Java_com_p2p_messenger_P2PLib_whiteboardErase<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, peer: JString<'local>, group_id: JString<'local>, ids: JByteArray<'local>) -> jstring {
        let (peer, gid) = (jstr(&mut env, &peer), jstr(&mut env, &group_id));
        let ids = jbytearray_to_vec(&mut env, &ids);
        let result = catch_panic(move || {
            let _guard = RUNTIME.enter();
            core_lock().wb_erase_strokes(&peer, &gid, &ids)
        });
        safe_new_jstring(&mut env, status(result))
    }

    #[no_mangle]
    pub extern "system" fn Java_com_p2p_messenger_P2PLib_whiteboardOpen<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, peer: JString<'local>, group_id: JString<'local>) {
        let (peer, gid) = (jstr(&mut env, &peer), jstr(&mut env, &group_id));
        let _ = catch_panic(move || {
            let _guard = RUNTIME.enter();
            core_lock().wb_open(&peer, &gid)
        });
    }

    #[no_mangle]
    pub extern "system" fn Java_com_p2p_messenger_P2PLib_whiteboardMarkRead<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, peer: JString<'local>, group_id: JString<'local>, page: jint) {
        let (peer, gid) = (jstr(&mut env, &peer), jstr(&mut env, &group_id));
        let _ = catch_panic(move || core_lock().wb_mark_read(&peer, &gid, page.clamp(0, 255) as u8));
    }

    #[no_mangle]
    pub extern "system" fn Java_com_p2p_messenger_P2PLib_whiteboardInfo<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, peer: JString<'local>, group_id: JString<'local>) -> jstring {
        let (peer, gid) = (jstr(&mut env, &peer), jstr(&mut env, &group_id));
        let out = match catch_panic(move || core_lock().wb_info(&peer, &gid)) {
            Ok(Ok(json)) => json,
            Ok(Err(e)) | Err(e) => format!("Error: {}", e),
        };
        safe_new_jstring(&mut env, out)
    }

    #[no_mangle]
    pub extern "system" fn Java_com_p2p_messenger_P2PLib_whiteboardPage<'local>(mut env: JNIEnv<'local>, _class: JClass<'local>, peer: JString<'local>, group_id: JString<'local>, page: jint) -> jbyteArray {
        let (peer, gid) = (jstr(&mut env, &peer), jstr(&mut env, &group_id));
        let bytes = catch_panic(move || core_lock().wb_page_blob(&peer, &gid, page.clamp(0, 255) as u8)).unwrap_or_default();
        bytes_to_jbytearray(&mut env, &bytes)
    }

    /// The UI's pen-up timer: sends what is due without waiting for the poll loop.
    #[no_mangle]
    pub extern "system" fn Java_com_p2p_messenger_P2PLib_whiteboardTick<'local>(_env: JNIEnv<'local>, _class: JClass<'local>) {
        let _ = catch_panic(|| {
            let _guard = RUNTIME.enter();
            core_lock().wb_sweep();
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn core() -> P2PCore {
        let mut core = P2PCore::new();
        core.skipped_key_encryption_key = Some([7u8; 32]);
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA).unwrap();
        conn.execute_batch("CREATE TABLE app_meta (k TEXT PRIMARY KEY, v BLOB NOT NULL);").unwrap();
        core.db = Some(conn);
        core
    }

    fn stroke(n: u8, page: u8) -> WbStroke {
        WbStroke { id: vec![n; 8], page, shade: 1, author: 0, width: 7, points: vec![10, 0, 20, 0, 30, 0, 40, 0] }
    }

    #[test]
    fn rejects_what_does_not_fit_the_canvas() {
        assert!(stroke_ok(&stroke(1, 0)));
        assert!(!stroke_ok(&WbStroke { id: vec![1; 7], ..stroke(1, 0) }));
        assert!(!stroke_ok(&stroke(1, MAX_PAGES)));
        assert!(!stroke_ok(&WbStroke { shade: 3, ..stroke(1, 0) }));
        assert!(!stroke_ok(&WbStroke { width: MAX_PEN_WIDTH + 1, ..stroke(1, 0) }));
        assert!(!stroke_ok(&WbStroke { points: vec![], ..stroke(1, 0) }));
        assert!(!stroke_ok(&WbStroke { points: vec![1, 2, 3], ..stroke(1, 0) }));
        assert!(!stroke_ok(&WbStroke { points: vec![0xFF, 0xFF, 0, 0], ..stroke(1, 0) }));
        assert!(!stroke_ok(&WbStroke { points: vec![0; (MAX_STROKE_POINTS + 1) * 4], ..stroke(1, 0) }));
    }

    #[test]
    fn points_are_sealed_at_rest_and_read_back() {
        let core = core();
        assert!(core.wb_insert("g:x", &stroke(1, 0), "alice"));
        let stored: Vec<u8> = core.db.as_ref().unwrap()
            .query_row("SELECT points FROM wb_strokes", [], |r| r.get(0)).unwrap();
        assert_ne!(stored, stroke(1, 0).points);
        assert_eq!(core.wb_page_strokes("g:x", 0), vec![(stroke(1, 0), "alice".to_string())]);
    }

    #[test]
    fn erase_wins_in_either_order_and_copies_converge() {
        // Device A: add, then erase. Device B: the erase arrives first.
        let (a, b) = (core(), core());
        assert!(a.wb_insert("g:x", &stroke(1, 0), "alice"));
        assert!(a.wb_insert("g:x", &stroke(2, 0), "alice"));
        assert_eq!(a.wb_erase("g:x", 0, &[1; 8]), Some(0));
        assert_eq!(b.wb_erase("g:x", 0, &[1; 8]), None);
        assert!(!b.wb_insert("g:x", &stroke(1, 0), "alice"), "a late copy of an erased stroke must not come back");
        assert!(b.wb_insert("g:x", &stroke(2, 0), "alice"));
        assert!(!b.wb_insert("g:x", &stroke(2, 0), "alice"), "duplicate");
        assert_eq!(a.wb_digest("g:x"), b.wb_digest("g:x"));
        assert_eq!(a.wb_digest("g:x"), vec![WbPageDigest { page: 0, count: 1, hash: id_u64(&[2; 8]) }]);
        assert_eq!(a.wb_page_tombstones("g:x", 0), vec![1; 8]);
    }

    #[test]
    fn a_page_stops_growing_at_its_budget_and_erasing_frees_it() {
        let core = core();
        let big = |n: u8| WbStroke { points: vec![0; MAX_STROKE_POINTS * 4], ..stroke(n, 0) };
        let mut added = 0u8;
        while core.wb_insert("g:x", &big(added), "alice") {
            added += 1;
        }
        assert!(added > 0 && (added as usize) <= MAX_PAGE_BYTES / (MAX_STROKE_POINTS * 4));
        assert!(!core.wb_insert("g:x", &big(200), "alice"));
        assert!(core.wb_insert("g:x", &stroke(201, 1), "alice"), "another page has its own budget");
        core.wb_erase("g:x", 0, &[0; 8]);
        assert!(core.wb_insert("g:x", &big(202), "alice"));
    }

    #[test]
    fn tombstones_are_capped() {
        let core = core();
        // One real erase first, then a flood of ids this device never held.
        assert!(core.wb_insert("g:x", &stroke(1, 0), "alice"));
        assert_eq!(core.wb_erase("g:x", 0, &[1; 8]), Some(0));
        for n in 1000..(1000 + MAX_TOMBSTONES as u64 + 10) {
            core.wb_erase("g:x", 0, &n.to_le_bytes());
        }
        core.wb_trim_tombstones("g:x");
        assert_eq!(core.wb_page_tombstones("g:x", 0).len(), MAX_TOMBSTONES * 8);
        assert!(core.wb_is_tombstoned("g:x", &[1; 8]), "a real erase outlives made-up ids");
        assert!(!core.wb_is_tombstoned("g:x", &1000u64.to_le_bytes()), "oldest made-up id dropped");
        assert!(core.wb_is_tombstoned("g:x", &(1000 + MAX_TOMBSTONES as u64 + 9).to_le_bytes()));
    }

    #[test]
    fn unread_is_a_bit_per_page_and_deleting_a_board_leaves_nothing() {
        let mut core = core();
        core.wb_insert("g:x", &stroke(1, 0), "alice");
        core.wb_erase("g:x", 0, &[9; 8]);
        core.wb_set_unread("g:x", 0b101);
        assert_eq!(core.wb_unread("g:x"), 0b101);
        core.wb_delete_board(Some("x"), None);
        assert_eq!(core.wb_unread("g:x"), 0);
        assert!(core.wb_digest("g:x").is_empty());
        assert!(core.wb_page_tombstones("g:x", 0).is_empty());
    }

    #[test]
    fn pulls_are_budgeted_per_device() {
        let mut core = core();
        assert!(core.wb_pull_allowed("pages", "g:x", "fp", MAX_PAGES as u64), "one whole board at once");
        assert!(!core.wb_pull_allowed("pages", "g:x", "fp", 1));
        assert!(core.wb_pull_allowed("pages", "g:x", "other", 1), "per device");
        assert!(core.wb_pull_allowed("digest", "g:x", "fp", 1), "per kind");
    }

    /// Every packet handler has to go through the authorization gate before it
    /// touches a board (same source-scan pattern as `authz_coverage_tests`).
    #[test]
    fn every_handler_goes_through_the_gate() {
        let src = include_str!("whiteboard.rs");
        for handler in ["fn wb_on_ops(", "fn wb_on_digest(", "fn wb_on_page_request(", "fn wb_on_page("] {
            let needle = format!("pub(crate) {}", handler);
            let body = &src[src.find(&needle).unwrap_or_else(|| panic!("{handler} not found"))..];
            let first_line_end = body.find('\n').unwrap();
            let second_line = &body[first_line_end + 1..];
            let second_line = &second_line[..second_line.find('\n').unwrap()];
            assert!(second_line.contains("self.wb_incoming_board("), "{handler} must start with the gate");
        }
    }
}
