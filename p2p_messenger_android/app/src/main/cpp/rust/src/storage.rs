//! Stickers, storage limits and pruning.

use super::*;

impl P2PCore {

    // ---------------------------------------------------------------
    // Attachments (files, photos, videos, voice). See the attachments/mod.rs module note; maximum size 4 GB.
    // Policy: the SENDER always keeps its own copy of a file it sent, regardless of its node mode. On the RECEIVING side, when node mode is on,
    // a new file offer is downloaded and stored automatically (see the receive_message FileOffer arm). When node mode is off, only the metadata
    // is shown and the download waits for the user's "Download" tap. This is the same rule as message-history archiving (stored locally only
    // while node mode is on), extended to file bytes.
    // ---------------------------------------------------------------

    pub(crate) fn attachments_dir(&self) -> Result<std::path::PathBuf, String> {
        let base = self.app_files_dir.as_ref().ok_or("initDatabase not called yet")?;
        Ok(std::path::Path::new(base).join("attachments"))
    }

    /// See `is_safe_file_id`, the LAST line of defence. Callers should already pass a validated id, but this function is the ONLY gate for building
    /// paths, so the check is repeated here. A future call path that forgets the check still cannot leave the directory.
    pub(crate) fn enc_path_for(&self, file_id: &str) -> Result<std::path::PathBuf, String> {
        if !is_safe_file_id(file_id) {
            return Err(format!("Invalid file_id (cannot be used as a path): {}", file_id));
        }
        Ok(self.attachments_dir()?.join(format!("{}.enc", file_id)))
    }

    /// Writes my stored sticker whose content hash is `sha256_hex` (the
    /// offer's) as `file_id`'s `.enc` under the offer's key and marks the row
    /// complete. Only my own store: its id is the hash the decrypt checks.
    pub(crate) fn reuse_local_sticker(&mut self, file_id: &str, file_key: &[u8; 32], chunk_size: usize, sha256_hex: &str) -> Result<(), String> {
        let conn = self.db.as_ref().ok_or("DB not open")?;
        let id: String = conn.query_row("SELECT id FROM stickers WHERE id = ?1", params![sha256_hex], |r| r.get(0))
            .map_err(|_| "No local copy".to_string())?;
        let plain = self.decrypt_sticker_to_tmp(&id)?;
        let dest = self.enc_path_for(file_id)?;
        let enc = attachments::encrypt_file_to_disk_with(&plain, &dest, file_key, chunk_size);
        let _ = std::fs::remove_file(&plain);
        let (total, sha) = enc.inspect_err(|_| { let _ = std::fs::remove_file(&dest); })?;
        let conn = self.db.as_ref().ok_or("DB not open")?;
        conn.execute(
            "UPDATE files SET sha256_hex = ?2, total_size = ?3, status = 'complete', bytes_transferred = ?3 WHERE file_id = ?1",
            params![file_id, sha, total as i64],
        ).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub(crate) fn stickers_dir(&self) -> Result<std::path::PathBuf, String> {
        let base = self.app_files_dir.as_ref().ok_or("initDatabase not called yet")?;
        Ok(std::path::Path::new(base).join("stickers"))
    }

    /// The `.enc` of sticker `id`; `id` must be a SHA-256 hex (it names a file).
    pub(crate) fn sticker_enc_path(&self, id: &str) -> Result<std::path::PathBuf, String> {
        if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("Bad sticker id".to_string());
        }
        Ok(self.stickers_dir()?.join(format!("{id}.enc")))
    }

    pub(crate) fn sticker_animated(&self, id: &str) -> Result<bool, String> {
        let conn = self.db.as_ref().ok_or("DB not open")?;
        conn.query_row("SELECT animated FROM stickers WHERE id = ?1", params![id], |r| r.get(0))
            .map_err(|_| "Unknown sticker".to_string())
    }

    pub(crate) fn sticker_file_key(&self, id: &str) -> Result<[u8; 32], String> {
        let conn = self.db.as_ref().ok_or("DB not open")?;
        let (encrypted_key, key_nonce): (Vec<u8>, Vec<u8>) = conn.query_row(
            "SELECT encrypted_key, key_nonce FROM stickers WHERE id = ?1", params![id], |r| Ok((r.get(0)?, r.get(1)?)),
        ).map_err(|_| "Unknown sticker".to_string())?;
        self.unwrap_file_key(&encrypted_key, &key_nonce)
    }

    /// Sticker `id` decrypted to a fresh temporary `.jxl`; the caller removes it.
    pub(crate) fn decrypt_sticker_to_tmp(&self, id: &str) -> Result<std::path::PathBuf, String> {
        let enc_path = self.sticker_enc_path(id)?;
        let file_key = self.sticker_file_key(id)?;
        let dir = self.attachments_dir()?.join("plain_cache");
        let _ = std::fs::create_dir_all(&dir);
        let tmp = dir.join(format!(".sticker-{}.jxl", uuid::Uuid::new_v4()));
        attachments::decrypt_file_from_disk_with(&enc_path, &tmp, &file_key, id, attachments::FILE_CHUNK_SIZE_V2)
            .inspect_err(|_| { let _ = std::fs::remove_file(&tmp); })?;
        Ok(tmp)
    }

    pub(crate) fn has_sticker_origin(&self, origin: &str) -> bool {
        valid_sticker_origin(origin)
            && self.db.as_ref().is_some_and(|c| c.query_row("SELECT 1 FROM stickers WHERE origin_id = ?1", params![origin], |_| Ok(())).is_ok())
    }

    /// Stores a plain sticker JPEG XL at `src` in my sticker store (encrypted
    /// at rest, like attachments); id = SHA-256 hex of the bytes, so the same
    /// sticker is kept once. `sync`: also send it to my other devices.
    pub(crate) fn store_sticker(&mut self, src: &std::path::Path, sync: bool, origin: Option<&str>) -> Result<String, String> {
        let animated = attachments::sticker_check(src)?;
        let dir = self.stickers_dir()?;
        let _ = std::fs::create_dir_all(&dir);
        let mut file_key = [0u8; 32];
        {
            use rand::RngCore;
            OsRng.fill_bytes(&mut file_key);
        }
        let (encrypted_key, key_nonce) = self.wrap_file_key(&file_key)?;
        let tmp = dir.join(format!(".tmp-{}", uuid::Uuid::new_v4()));
        let (_, id) = attachments::encrypt_file_to_disk_with(src, &tmp, &file_key, attachments::FILE_CHUNK_SIZE_V2)
            .inspect_err(|_| { let _ = std::fs::remove_file(&tmp); })?;
        let conn = self.db.as_ref().ok_or("DB not open")?;
        let origin = origin.filter(|o| valid_sticker_origin(o)).map_or_else(|| format!("jxl:{id}"), str::to_string);
        // Same bytes, or the same origin (a WhatsApp sticker encoded twice): kept once.
        if let Ok(have) = conn.query_row("SELECT id FROM stickers WHERE id = ?1 OR origin_id = ?2", params![id, origin], |r| r.get::<_, String>(0)) {
            if self.sticker_enc_path(&have).is_ok_and(|p| p.exists()) {
                let _ = std::fs::remove_file(&tmp);
                return Ok(have);
            }
            // The row's file is gone (interrupted restore, manual cleanup): this copy replaces the row.
            let _ = conn.execute("DELETE FROM stickers WHERE id = ?1", params![have]);
        }
        let enc = dir.join(format!("{id}.enc"));
        std::fs::rename(&tmp, &enc).inspect_err(|_| { let _ = std::fs::remove_file(&tmp); }).map_err(|e| e.to_string())?;
        // No row, no file: an orphan was never listed nor cleaned.
        conn.execute(
            "INSERT INTO stickers (id, created_at, animated, encrypted_key, key_nonce, origin_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![id, current_time_ms() as i64, animated, encrypted_key, key_nonce, origin],
        ).inspect_err(|_| { let _ = std::fs::remove_file(&enc); }).map_err(|e| e.to_string())?;
        if sync {
            match std::fs::read(src) {
                Ok(jxl) => {
                    for body in sticker_echo_parts(&id, &jxl, Some(origin)) {
                        self.send_to_siblings(body);
                    }
                }
                Err(e) => warn!("Sticker {} not synced: {}", id, e),
            }
        }
        Ok(id)
    }

    pub(crate) fn sticker_ids(&self) -> Vec<String> {
        let Some(conn) = &self.db else { return Vec::new() };
        conn.prepare("SELECT id FROM stickers ORDER BY created_at")
            .and_then(|mut stmt| stmt.query_map([], |r| r.get::<_, String>(0))?.collect())
            .unwrap_or_default()
    }

    /// One sticker of my store to sibling `fp` (a `StickersRequest` answer).
    pub(crate) fn send_sticker_to_sibling(&mut self, fp: &str, id: &str) {
        let origin = self.db.as_ref().and_then(|c| {
            c.query_row("SELECT origin_id FROM stickers WHERE id = ?1", params![id], |r| r.get::<_, Option<String>>(0)).ok().flatten()
        });
        let jxl = self.decrypt_sticker_to_tmp(id).and_then(|tmp| {
            let r = std::fs::read(&tmp).map_err(|e| e.to_string());
            let _ = std::fs::remove_file(&tmp);
            r
        });
        match jxl {
            Ok(jxl) => {
                for body in sticker_echo_parts(id, &jxl, origin.clone()) {
                    let content = MessageContent::SiblingEcho { conversation_identity_id: None, group_id: None, body };
                    if let Err(e) = self.send_message_content(fp.to_string(), &content, None) {
                        error!("Sticker {} to sibling {} not sent: {}", id, crate::log_id(fp), e);
                        return;
                    }
                }
            }
            Err(e) => warn!("Sticker {} not sent: {}", id, e),
        }
    }

    /// Asks my other devices for their sticker store; the root device answers
    /// with the ones this device lacks.
    pub(crate) fn request_stickers_from_siblings(&mut self) -> Result<(), String> {
        let siblings = self.sibling_active_devices();
        if siblings.is_empty() {
            return Err("No linked device reachable".to_string());
        }
        let content = MessageContent::SiblingEcho { conversation_identity_id: None, group_id: None, body: SiblingEchoBody::StickersRequest { have: self.sticker_ids() } };
        for fp in siblings {
            if let Err(e) = self.send_message_content(fp.clone(), &content, None) {
                error!("StickersRequest to {} not sent: {}", crate::log_id(&fp), e);
            }
        }
        Ok(())
    }

    pub(crate) fn delete_sticker(&mut self, id: &str, sync: bool) -> Result<(), String> {
        self.delete_stickers(&[id.to_string()], sync)
    }

    /// Deletes every sticker in `ids` and tells my other devices in ONE echo. Returns the first error after
    /// trying them all.
    pub(crate) fn delete_stickers(&mut self, ids: &[String], sync: bool) -> Result<(), String> {
        let mut first_err = None;
        let mut done = Vec::new();
        for id in ids {
            match self.delete_sticker_here(id) {
                Ok(()) => done.push(id.clone()),
                Err(e) => { first_err.get_or_insert(e); }
            }
        }
        if sync && !done.is_empty() {
            self.send_to_siblings(SiblingEchoBody::StickerRemoved { ids: done });
        }
        first_err.map_or(Ok(()), Err)
    }

    fn delete_sticker_here(&mut self, id: &str) -> Result<(), String> {
        let enc_path = self.sticker_enc_path(id)?;
        let conn = self.db.as_ref().ok_or("DB not open")?;
        conn.execute("DELETE FROM stickers WHERE id = ?1", params![id]).map_err(|e| e.to_string())?;
        let _ = conn.execute("DELETE FROM sticker_folder_items WHERE sticker_id = ?1", params![id]);
        let _ = std::fs::remove_file(enc_path);
        let cache = self.attachments_dir()?.join("plain_cache");
        let _ = std::fs::remove_file(cache.join(format!("sticker-{id}.png")));
        let _ = std::fs::remove_file(cache.join(format!("anim-{id}.gif")));
        let _ = std::fs::remove_file(cache.join(format!("first-{id}.png")));
        remove_cached_conversions(&self.attachments_dir()?, "sticker-", id);
        Ok(())
    }

    /// Sets or clears the favorite flag of a sticker.
    /// ponytail: favorites stay on this device (not synced to siblings).
    pub(crate) fn set_sticker_favorite(&self, id: &str, favorite: bool) -> Result<(), String> {
        let conn = self.db.as_ref().ok_or("DB not open")?;
        conn.execute("UPDATE stickers SET favorite = ?2 WHERE id = ?1", params![id, favorite]).map_err(|e| e.to_string())?;
        Ok(())
    }

    /// JSON `[{id, animated, created_at, favorite}]`, favorites first, then newest.
    pub(crate) fn list_stickers(&self) -> String {
        let Some(conn) = &self.db else { return "[]".to_string() };
        let rows: Vec<serde_json::Value> = conn.prepare("SELECT id, animated, created_at, favorite FROM stickers ORDER BY favorite DESC, created_at DESC")
            .and_then(|mut stmt| stmt.query_map([], |r| Ok(serde_json::json!({
                "id": r.get::<_, String>(0)?, "animated": r.get::<_, bool>(1)?, "created_at": r.get::<_, i64>(2)?,
                "favorite": r.get::<_, bool>(3)?,
            })))?.collect())
            .unwrap_or_default();
        serde_json::Value::from(rows).to_string()
    }

    /// JSON `[{id, name, stickers: [sticker id]}]`, oldest folder first. Only stickers still in the store.
    /// ponytail: folders stay on this device (not synced to siblings), like favorites.
    pub(crate) fn list_sticker_folders(&self) -> String {
        let Some(conn) = &self.db else { return "[]".to_string() };
        let folders: Vec<(i64, String)> = conn.prepare("SELECT id, name FROM sticker_folders ORDER BY created_at, id")
            .and_then(|mut stmt| stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect())
            .unwrap_or_default();
        let rows: Vec<serde_json::Value> = folders.into_iter().map(|(id, name)| {
            let stickers: Vec<String> = conn.prepare(
                "SELECT i.sticker_id FROM sticker_folder_items i JOIN stickers s ON s.id = i.sticker_id WHERE i.folder_id = ?1",
            )
                .and_then(|mut stmt| stmt.query_map(params![id], |r| r.get(0))?.collect())
                .unwrap_or_default();
            serde_json::json!({ "id": id, "name": name, "stickers": stickers })
        }).collect();
        serde_json::Value::from(rows).to_string()
    }

    /// Creates a sticker folder. Returns its id.
    pub(crate) fn create_sticker_folder(&self, name: &str) -> Result<i64, String> {
        let name = sticker_folder_name(name)?;
        let conn = self.db.as_ref().ok_or("DB not open")?;
        conn.execute("INSERT INTO sticker_folders (name, created_at) VALUES (?1, ?2)", params![name, current_time_ms() as i64])
            .map_err(|e| e.to_string())?;
        Ok(conn.last_insert_rowid())
    }

    pub(crate) fn rename_sticker_folder(&self, id: i64, name: &str) -> Result<(), String> {
        let name = sticker_folder_name(name)?;
        let conn = self.db.as_ref().ok_or("DB not open")?;
        match conn.execute("UPDATE sticker_folders SET name = ?2 WHERE id = ?1", params![id, name]).map_err(|e| e.to_string())? {
            0 => Err("No such folder".to_string()),
            _ => Ok(()),
        }
    }

    /// Deletes the folder only: its stickers stay in the store.
    pub(crate) fn delete_sticker_folder(&self, id: i64) -> Result<(), String> {
        let conn = self.db.as_ref().ok_or("DB not open")?;
        let tx = conn.unchecked_transaction().map_err(|e| e.to_string())?;
        tx.execute("DELETE FROM sticker_folder_items WHERE folder_id = ?1", params![id]).map_err(|e| e.to_string())?;
        tx.execute("DELETE FROM sticker_folders WHERE id = ?1", params![id]).map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())
    }

    /// Adds stickers to a folder; ones already in it, or not in the store, are skipped.
    pub(crate) fn add_stickers_to_folder(&self, id: i64, sticker_ids: &[String]) -> Result<(), String> {
        let conn = self.db.as_ref().ok_or("DB not open")?;
        let exists = conn.query_row("SELECT 1 FROM sticker_folders WHERE id = ?1", params![id], |_| Ok(())).is_ok();
        if !exists {
            return Err("No such folder".to_string());
        }
        let tx = conn.unchecked_transaction().map_err(|e| e.to_string())?;
        for sticker in sticker_ids {
            tx.execute(
                "INSERT OR IGNORE INTO sticker_folder_items (folder_id, sticker_id) SELECT ?1, id FROM stickers WHERE id = ?2",
                params![id, sticker],
            ).map_err(|e| e.to_string())?;
        }
        tx.commit().map_err(|e| e.to_string())
    }

    /// Takes stickers out of a folder; they stay in the store.
    pub(crate) fn remove_stickers_from_folder(&self, id: i64, sticker_ids: &[String]) -> Result<(), String> {
        let conn = self.db.as_ref().ok_or("DB not open")?;
        let tx = conn.unchecked_transaction().map_err(|e| e.to_string())?;
        for sticker in sticker_ids {
            tx.execute("DELETE FROM sticker_folder_items WHERE folder_id = ?1 AND sticker_id = ?2", params![id, sticker])
                .map_err(|e| e.to_string())?;
        }
        tx.commit().map_err(|e| e.to_string())
    }

    /// A sibling echo with no chat (sticker store, contact and block changes) to all my other devices.
    pub(crate) fn send_to_siblings(&mut self, body: SiblingEchoBody) {
        let content = MessageContent::SiblingEcho { conversation_identity_id: None, group_id: None, body };
        let siblings = self.sibling_active_devices();
        self.journal_sibling_op(&content, &siblings);
        for fp in siblings {
            if let Err(e) = self.send_message_content(fp.clone(), &content, None) {
                error!("SiblingEcho send failed (sibling={}): {}", crate::log_id(&fp), e);
            }
        }
    }

    /// Applies `history_storage_limit_bytes` live. It runs ONLY while node mode is on. The limit exists because node mode auto-downloads aggressively
    /// (see the field docs). A device with node mode off does not accumulate files without the user asking. If the total size of completed files
    /// exceeds the limit, it removes local copies of received files, OLDEST first (by ascending created_at), until the total is under the limit. Each
    /// removed file loses its `.enc` and any `plain_cache` copy, and its row goes back to 'offered' (see `remove_local_attachment`). Sent files are
    /// never removed.
    pub(crate) fn enforce_history_storage_limit(&mut self) {
        if !self.node_mode_enabled {
            return;
        }
        self.evict_failed_partials();
        let limit = self.history_storage_limit_bytes;
        let conn = match &self.db {
            Some(c) => c,
            None => return,
        };
        // Downloads in progress count too (they are on disk already), or a
        // peer could fill the disk with offers the quota never sees. Only
        // complete files are evicted below.
        // What a download has on disk, not the size its sender declared: two
        // offers of `limit` bytes that never served a chunk evicted every
        // complete file, own sent files included.
        let (complete, partial): (i64, i64) = conn.query_row(
            "SELECT COALESCE(SUM(CASE status WHEN 'complete' THEN total_size ELSE 0 END), 0), \
                    COALESCE(SUM(CASE status WHEN 'complete' THEN 0 ELSE bytes_transferred END), 0) \
             FROM files WHERE status IN ('complete', 'downloading', 'failed') AND direction != 'sent'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        ).unwrap_or((0, 0));
        let total = complete.saturating_add(partial);
        if total < 0 || (total as u64) <= limit {
            return;
        }
        // Evicting complete files cannot free what downloads hold, and
        // charging them here let a few running downloads empty the store:
        // in-flight bytes are bounded at offer time (`receive_file_offer`).
        // Sent files are neither counted nor evicted: their copy is what peers
        // download from, and counting what can never be freed evicted every
        // received file once the sent ones alone filled the limit. A received file loses only this device's copy and
        // goes back to 'offered': deleting the row took the
        // bubble with it, and one contact's files evicted everyone else's.
        let mut stmt = match conn.prepare(
            "SELECT file_id, total_size, created_at FROM files WHERE status = 'complete' AND direction != 'sent' ORDER BY created_at ASC"
        ) {
            Ok(s) => s,
            Err(_) => return,
        };
        let rows: Vec<(String, i64, i64)> = match stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?))) {
            Ok(rows) => rows.flatten().collect(),
            Err(_) => return,
        };
        drop(stmt);

        // Fix: the SENDING device may delete a file to enforce its own storage limit while the recipient has not downloaded it yet, or has not started.
        // Before this, the pass deleted strictly OLDEST first until under the limit, so even a freshly completed file (one whose download had not
        // started yet) could be deleted right away when the total was large. Now rows newer than `FILE_RETENTION_GRACE_MS` count as PROTECTED
        // and are skipped. Rows are sorted by `created_at ASC`, so once the first protected row is reached, every later row is protected too, and
        // the first pass stops there.
        let now = current_time_ms();
        let mut remaining = complete.max(0) as u64;
        let mut to_delete = Vec::new();
        let mut protected_from_idx = rows.len();
        for (i, (file_id, size, created_at)) in rows.iter().enumerate() {
            if remaining <= limit {
                protected_from_idx = i;
                break;
            }
            let age = now.saturating_sub((*created_at).max(0) as u64);
            if age < FILE_RETENTION_GRACE_MS {
                protected_from_idx = i;
                break;
            }
            to_delete.push(file_id.clone());
            remaining = remaining.saturating_sub((*size).max(0) as u64);
        }
        // EXCEPTION: even with the protected (recent enough) files EXCLUDED, if the limit the user explicitly set is still exceeded (for example the
        // user lowered the limit to a very small value), that limit still takes priority. In that case recent files are evicted too, oldest first.
        if remaining > limit {
            warn!(
                "history_storage_limit ({} bytes) is exceeded even excluding protected files (newer than {} hours) — the user's limit takes priority, those will be evicted too if needed",
                limit, FILE_RETENTION_GRACE_MS / 3_600_000
            );
            for (file_id, size, _) in &rows[protected_from_idx..] {
                if remaining <= limit {
                    break;
                }
                to_delete.push(file_id.clone());
                remaining = remaining.saturating_sub((*size).max(0) as u64);
            }
        }
        let deleted_count = to_delete.len();
        for file_id in to_delete {
            let _ = self.remove_local_attachment(&file_id);
        }
        if deleted_count > 0 {
            info!(
                "history_storage_limit ({} bytes) exceeded — {} oldest files deleted (remaining usage ~{} bytes)",
                limit, deleted_count, remaining
            );
        }
    }

    /// Failed partial downloads go first, oldest first, back to 'offered': kept only for a resume, they were never evicted, and offers that
    /// stop being served filled the disk past the limit.
    pub(crate) fn evict_failed_partials(&mut self) {
        let limit = self.history_storage_limit_bytes;
        let Some(conn) = &self.db else { return };
        let total: i64 = conn.query_row(
            "SELECT COALESCE(SUM(CASE status WHEN 'complete' THEN total_size ELSE bytes_transferred END), 0) \
             FROM files WHERE status IN ('complete', 'downloading', 'failed') AND direction != 'sent'",
            [], |r| r.get(0),
        ).unwrap_or(0);
        let mut over = (total.max(0) as u64).saturating_sub(limit);
        if over == 0 {
            return;
        }
        let failed: Vec<(String, i64)> = conn
            .prepare("SELECT file_id, bytes_transferred FROM files WHERE status = 'failed' AND direction = 'received' AND bytes_transferred > 0 ORDER BY created_at ASC")
            .and_then(|mut st| st.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).map(|it| it.flatten().collect()))
            .unwrap_or_default();
        for (file_id, bytes) in failed {
            if over == 0 {
                break;
            }
            if self.active_downloads.contains_key(&file_id) {
                continue;
            }
            if self.remove_local_attachment(&file_id).is_ok() {
                over = over.saturating_sub(bytes.max(0) as u64);
            }
        }
    }

    /// `.enc` files in `attachments/` with no `files` row: left by a process killed while encrypting an outgoing file (the row is written
    /// only when the encryption is done). Only files untouched for an hour, so no encryption still running is hit. Called at start.
    pub(crate) fn sweep_orphan_enc_files(&self) {
        let (Some(conn), Ok(dir)) = (&self.db, self.attachments_dir()) else { return };
        // Temporary files of a sticker store or a conversion cache write a killed process left; nothing runs yet at start.
        for (tmp_dir, prefix, suffix) in [(self.stickers_dir().ok(), ".tmp-", ""), (Some(dir.join("sticker_cache")), ".", ".tmp")] {
            let Some(entries) = tmp_dir.and_then(|d| std::fs::read_dir(d).ok()) else { continue };
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with(prefix) && name.ends_with(suffix) {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
        }
        let Ok(entries) = std::fs::read_dir(&dir) else { return };
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(id) = path.file_name().and_then(|n| n.to_str()).and_then(|n| n.strip_suffix(".enc")) else { continue };
            let old = entry.metadata().ok().and_then(|m| m.modified().ok())
                .and_then(|t| t.elapsed().ok())
                .map_or(false, |age| age.as_secs() > 3600);
            if !old || !is_safe_file_id(id) {
                continue;
            }
            let known = conn.query_row("SELECT 1 FROM files WHERE file_id = ?1", params![id], |_| Ok(())).is_ok();
            if !known {
                info!("Orphan attachment file removed: {}", id);
                let _ = std::fs::remove_file(&path);
            }
        }
    }

    /// Called from `poll_events`. This is a SAFETY NET in addition to the calls to `enforce_history_storage_limit` at file-completion time. It
    /// trims files that have already accumulated, for example after the user LOWERS the limit. It is rate limited by
    /// `HISTORY_STORAGE_SWEEP_INTERVAL_MS` (so a full SQL SUM query does not run on every turn).
    pub(crate) fn periodic_storage_sweep(&mut self) {
        let now = current_time_ms();
        if now.saturating_sub(self.last_storage_sweep_at) < HISTORY_STORAGE_SWEEP_INTERVAL_MS {
            return;
        }
        self.last_storage_sweep_at = now;
        // Acked packet ids are kept as long as the sender can still retry
        // the packet; pruned here instead of on every ack.
        if let Some(conn) = &self.db {
            let _ = conn.execute("DELETE FROM acked_packets WHERE acked_at < ?1", params![now.saturating_sub(TEXT_RETRY_GIVE_UP_MS) as i64]);
        }
        self.enforce_history_storage_limit();
    }

    /// Called from `delete_message`/`delete_group_message` and the receive-side
    /// `Delete` arm. An attachment bubble's `target_message_id` is the
    /// attachment's `file_id` (see ChatActivity/GroupChatActivity
    /// `onAttachmentLongClicked`), so checking the `files` table is how we
    /// tell a text delete from an attachment delete. If found, removes the
    /// on-disk copy + DB row via `delete_attachment_file`.
    pub(crate) fn purge_attachment_if_exists(&mut self, file_id: &str) {
        let exists = self.db.as_ref().map(|conn| {
            conn.query_row("SELECT 1 FROM files WHERE file_id = ?1", params![file_id], |_| Ok(()))
                .is_ok()
        }).unwrap_or(false);
        if exists {
            self.delete_attachment_file(file_id);
        }
    }

    /// Removes one attachment completely (the DB row, the on-disk `.enc` blob, and any `plain_cache` copy).
    pub(crate) fn delete_attachment_file(&mut self, file_id: &str) {
        self.remove_attachment_copy_with(file_id, true, false);
        self.finish_blob_upload(file_id);
        self.attachment_events.push(serde_json::json!({"type": "file_evicted", "file_id": file_id}).to_string());
    }

    /// Removes this device's copy of an attachment (`.enc`, decrypted cache,
    /// running transfer); the `files` row is the caller's business.
    pub(crate) fn remove_attachment_copy(&mut self, file_id: &str) {
        self.remove_attachment_copy_with(file_id, false, false);
    }

    /// Only the decrypted copies of an attachment; the `.enc` and the row stay (my hidden disappearing file, still served, see `expire_due`).
    pub(crate) fn remove_attachment_plain(&mut self, file_id: &str) {
        self.remove_attachment_copy_with(file_id, false, true);
    }

    /// `drop_row`: the `files` row is deleted too, before the `.enc`: a kill in between leaves an orphan `.enc`
    /// (swept at start), not a 'complete' row with no file.
    fn remove_attachment_copy_with(&mut self, file_id: &str, drop_row: bool, keep_enc: bool) {
        let (file_name, sha): (Option<String>, Option<String>) = self.db.as_ref().and_then(|conn| {
            conn.query_row("SELECT file_name, sha256_hex FROM files WHERE file_id = ?1", params![file_id], |r| Ok((r.get(0)?, r.get(1)?))).ok()
        }).unwrap_or_default();
        // Conversions named by content hash (`anim-<sha>.gif`, `first-<sha>.png`)
        // are shared: removed only when no other copy or sticker uses them.
        let sha = sha.filter(|h| h.len() == 64 && h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
        let shared = sha.as_deref().is_some_and(|h| self.db.as_ref().is_some_and(|conn| conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM files WHERE sha256_hex = ?1 AND file_id != ?2 AND status = 'complete')
                 OR EXISTS(SELECT 1 FROM stickers WHERE id = ?1)",
            params![h, file_id], |r| r.get::<_, bool>(0),
        ).unwrap_or(true)));
        if let (Some(h), false, Ok(dir)) = (sha.as_deref(), shared, self.attachments_dir()) {
            let _ = std::fs::remove_file(dir.join("plain_cache").join(format!("anim-{h}.gif")));
            let _ = std::fs::remove_file(dir.join("plain_cache").join(format!("first-{h}.png")));
        }
        if drop_row {
            if let Some(conn) = &self.db {
                let _ = conn.execute("DELETE FROM files WHERE file_id = ?1", params![file_id]);
            }
        }
        if let Some(enc_path) = self.enc_path_for(file_id).ok().filter(|_| !keep_enc) {
            let _ = std::fs::remove_file(enc_path);
        }
        if let Some(name) = file_name {
            // See `safe_extension`. The delete path must also not be able to leave the directory through the extension.
            let ext = safe_extension(&name);
            if is_safe_file_id(file_id) {
                if let Ok(dir) = self.attachments_dir() {
                    let _ = std::fs::remove_file(dir.join("plain_cache").join(format!("{}{}", file_id, ext)));
                    // A JPEG XL is opened as PNG, an animated one as GIF
                    // (`attachment_plaintext_path_unlocked`).
                    let _ = std::fs::remove_file(dir.join("plain_cache").join(format!("{}.png", file_id)));
                    let _ = std::fs::remove_file(dir.join("plain_cache").join(format!("{}.gif", file_id)));
                    // "Save as JPEG XL" (`attachment_original_path_unlocked`).
                    let _ = std::fs::remove_file(dir.join("plain_cache").join(format!("orig-{}.jxl", file_id)));
                    remove_cached_conversions(&dir, "att-", file_id);
                }
            }
        }
        // A transfer still running for this file: left alone it kept
        // `has_pending_work` (and the wake lock) up and wrote the file again.
        self.active_downloads.remove(file_id);
        self.download_request_ids.retain(|_, (fid, _)| fid != file_id);
    }

    /// Settings → Storage. Sizes are the files on disk (`total_size` is the
    /// sender's claim). JSON: `{"db_bytes", "attachments_bytes",
    /// "voice_bytes", "stickers_bytes", "cache_bytes", "chats":[{"kind":
    /// "contact"|"group", "id", "name", "bytes", "count"}]}`; `chats` holds
    /// every chat, biggest attachment usage first.
    pub(crate) fn storage_usage(&self) -> serde_json::Value {
        let Some(base) = self.app_files_dir.as_deref() else {
            return serde_json::json!({"chats": []});
        };
        let base_path = std::path::Path::new(base);
        // The WAL is part of the open DB.
        let db_bytes = ["", "-wal", "-shm"]
            .iter()
            .map(|suffix| disk_size(&base_path.join(format!("{}{}", DB_NAME, suffix))))
            .sum::<u64>();
        let attachments_dir = base_path.join("attachments");
        let enc_bytes = dir_size(&attachments_dir, Some("enc"));
        // Decrypted copies and the encrypted conversion cache.
        let cache_bytes = dir_size(&attachments_dir.join("plain_cache"), None) + dir_size(&attachments_dir.join("sticker_cache"), None);
        let stickers_bytes = dir_size(&base_path.join("stickers"), None);

        // (file_id, group_id, peer fingerprint, is a voice message, sent by me)
        let rows: Vec<(String, Option<String>, String, bool, bool)> = self.db.as_ref().and_then(|conn| {
            let mut stmt = conn.prepare(
                "SELECT file_id, group_id, peer_device_fingerprint, mime_type LIKE 'audio/%' AND duration_ms IS NOT NULL, direction = 'sent' FROM files",
            ).ok()?;
            let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))).ok()?
                .flatten()
                .collect();
            Some(rows)
        }).unwrap_or_default();
        // A contact's attachments from all its devices are one chat.
        let mut fp_identity: HashMap<String, String> = HashMap::new();
        let mut identity_name: HashMap<String, String> = HashMap::new();
        for contact in self.contacts.values() {
            identity_name.insert(contact.trusted_identity_id.clone(), contact.display_name.clone());
            for fp in self.contact_fingerprints_all(contact) {
                fp_identity.insert(fp, contact.trusted_identity_id.clone());
            }
        }
        let mut voice_bytes = 0u64;
        // (kind, id) -> (name, bytes, count)
        let mut usage: HashMap<(&str, String), (String, u64, u64)> = HashMap::new();
        for (file_id, group_id, peer_fp, voice, sent) in rows {
            let bytes = self.enc_path_for(&file_id).map(|p| disk_size(&p)).unwrap_or(0);
            if bytes == 0 {
                continue;
            }
            if voice {
                voice_bytes += bytes;
            }
            // My own outgoing file: the only source, not removable (see
            // `remove_local_attachment`), so not listed per chat.
            if sent {
                continue;
            }
            let (kind, id, name) = match group_id {
                Some(gid) => {
                    let name = self.groups.get(&gid).map(|g| g.name.clone()).unwrap_or_else(|| gid.clone());
                    ("group", gid, name)
                }
                None => {
                    let identity = fp_identity.get(&peer_fp);
                    // The fingerprint the chat screen is opened with.
                    let id = identity
                        .and_then(|i| self.canonical_device_for_identity(i))
                        .unwrap_or_else(|| self.canonical_peer_key(&peer_fp));
                    let name = identity
                        .and_then(|i| identity_name.get(i).cloned())
                        .unwrap_or_else(|| peer_fp.chars().take(8).collect());
                    ("contact", id, name)
                }
            };
            let entry = usage.entry((kind, id)).or_insert((name, 0, 0));
            entry.1 += bytes;
            entry.2 += 1;
        }
        // Chats without a local attachment too: their messages can be pruned.
        for contact in self.contacts.values() {
            if let Some(id) = self.canonical_device_for_identity(&contact.trusted_identity_id) {
                usage.entry(("contact", id)).or_insert((contact.display_name.clone(), 0, 0));
            }
        }
        for (gid, g) in &self.groups {
            usage.entry(("group", gid.clone())).or_insert((g.name.clone(), 0, 0));
        }
        let mut chats: Vec<_> = usage.into_iter().collect();
        chats.sort_by(|a, b| b.1.1.cmp(&a.1.1).then_with(|| a.1.0.cmp(&b.1.0)));
        let chats = chats
            .into_iter()
            .map(|((kind, id), (name, bytes, count))| {
                serde_json::json!({"kind": kind, "id": id, "name": name, "bytes": bytes, "count": count})
            })
            .collect::<Vec<_>>();
        serde_json::json!({
            "db_bytes": db_bytes,
            "attachments_bytes": enc_bytes.saturating_sub(voice_bytes),
            "voice_bytes": voice_bytes,
            "stickers_bytes": stickers_bytes,
            "cache_bytes": cache_bytes,
            "chats": chats,
        })
    }

    /// The devices (1:1) or group a storage chat id (`storage_usage`) names:
    /// `(fingerprints, group_id, history floor key)`.
    pub(crate) fn chat_prune_scope(&self, kind: &str, id: &str) -> Option<(Vec<String>, Option<String>, String)> {
        if kind == "group" {
            // A group left or deleted keeps its rows until the user prunes
            // them here: the id need not be a held group.
            return (self.groups.contains_key(id) || is_group_id(id)).then(|| (Vec::new(), Some(id.to_string()), id.to_string()));
        }
        let contact = self.contacts.values().find(|c| self.contact_fingerprints_all(c).iter().any(|f| f == id))?;
        Some((self.contact_fingerprints_all(contact), None, contact.trusted_identity_id.clone()))
    }

    /// Storage → "delete older than": what `prune_chat_before` would remove.
    /// `{"oldest_ms", "msg_count", "msg_bytes", "del_msg_count", "del_msg_bytes",
    /// "att_bytes", "del_att_bytes"}`; message bytes are the sealed blobs,
    /// attachment bytes the local copies. `before_ms` 0: nothing deleted.
    pub(crate) fn chat_prune_stats(&self, kind: &str, id: &str, before_ms: i64) -> serde_json::Value {
        let (Some((fps, group, _)), Some(conn)) = (self.chat_prune_scope(kind, id), self.db.as_ref()) else {
            return serde_json::json!({});
        };
        const T: &str = "COALESCE(NULLIF(sent_at_ms,0), timestamp)";
        let (mut oldest, mut mc, mut mb, mut dmc, mut dmb) = (i64::MAX, 0u64, 0u64, 0u64, 0u64);
        let mut msg_sql = |where_: &str, p: &str| {
            let sql = format!("SELECT {T}, length(encrypted_blob) FROM messages WHERE {where_}");
            let Ok(mut stmt) = conn.prepare(&sql) else { return };
            let Ok(rows) = stmt.query_map(params![p], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?))) else { return };
            for (t, len) in rows.flatten() {
                oldest = oldest.min(t);
                mc += 1;
                mb += len as u64;
                if t < before_ms {
                    dmc += 1;
                    dmb += len as u64;
                }
            }
        };
        match &group {
            Some(g) => msg_sql("group_id = ?1", g),
            None => fps.iter().for_each(|f| msg_sql("peer_device_fingerprint = ?1 AND group_id IS NULL", f)),
        }
        let (mut ab, mut dab) = (0u64, 0u64);
        for (file_id, created) in self.chat_prune_files(&fps, group.as_deref()) {
            let bytes = self.enc_path_for(&file_id).map(|p| disk_size(&p)).unwrap_or(0);
            ab += bytes;
            if created < before_ms {
                dab += bytes;
            }
        }
        serde_json::json!({
            "oldest_ms": if oldest == i64::MAX { 0 } else { oldest },
            "msg_count": mc, "msg_bytes": mb, "del_msg_count": dmc, "del_msg_bytes": dmb,
            "att_bytes": ab, "del_att_bytes": dab,
        })
    }

    /// `(file_id, created_at)` of a chat's attachment rows.
    pub(crate) fn chat_prune_files(&self, fps: &[String], group: Option<&str>) -> Vec<(String, i64)> {
        let Some(conn) = &self.db else { return Vec::new() };
        let mut out = Vec::new();
        let mut q = |sql: &str, p: &str| {
            if let Ok(mut stmt) = conn.prepare(sql) {
                if let Ok(rows) = stmt.query_map(params![p], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))) {
                    out.extend(rows.flatten());
                }
            }
        };
        match group {
            Some(g) => q("SELECT file_id, created_at FROM files WHERE group_id = ?1", g),
            None => fps.iter().for_each(|f| q("SELECT file_id, created_at FROM files WHERE peer_device_fingerprint = ?1 AND group_id IS NULL", f)),
        }
        out
    }

    /// Storage → "delete older than": this device's messages and attachments
    /// of one chat older than `before_ms`; the pairing and newer history stay.
    pub(crate) fn prune_chat_before(&mut self, kind: &str, id: &str, before_ms: i64) -> Result<(), String> {
        let (fps, group, floor_key) = self.chat_prune_scope(kind, id).ok_or("Chat not found")?;
        if before_ms <= 0 {
            return Ok(());
        }
        let old_files: Vec<String> = self.chat_prune_files(&fps, group.as_deref()).into_iter()
            .filter(|(_, created)| *created < before_ms)
            .map(|(file_id, _)| file_id)
            .collect();
        let conn = self.db.as_ref().ok_or("No DB")?;
        let tx = conn.unchecked_transaction().map_err(|e| e.to_string())?;
        // Reactions and seen marks on the attachments, before their rows go.
        for file_id in &old_files {
            tx.execute("DELETE FROM message_reactions WHERE message_id = ?1", params![file_id]).map_err(|e| e.to_string())?;
            tx.execute("DELETE FROM message_seen WHERE message_id = ?1", params![file_id]).map_err(|e| e.to_string())?;
        }
        let (cond, keys): (&str, Vec<&String>) = match &group {
            Some(g) => ("group_id = ?1", vec![g]),
            None => ("peer_device_fingerprint = ?1 AND group_id IS NULL", fps.iter().collect()),
        };
        // My messages still on their way: their queued sends are withdrawn after the commit.
        let mut unsent: Vec<String> = Vec::new();
        for k in keys {
            let old = format!("{cond} AND COALESCE(NULLIF(sent_at_ms,0), timestamp) < ?2");
            if let Ok(mut st) = tx.prepare(&format!("SELECT message_id FROM messages WHERE {old} AND status IN ('pending', 'sent') AND message_id IS NOT NULL")) {
                if let Ok(rows) = st.query_map(params![k, before_ms], |r| r.get::<_, String>(0)) {
                    unsent.extend(rows.flatten());
                }
            }
            for sql in [
                format!("DELETE FROM message_reactions WHERE message_id IN (SELECT message_id FROM messages WHERE {old})"),
                format!("DELETE FROM message_seen WHERE message_id IN (SELECT message_id FROM messages WHERE {old})"),
                format!("DELETE FROM messages WHERE {old}"),
            ] {
                tx.execute(&sql, params![k, before_ms]).map_err(|e| e.to_string())?;
            }
        }
        tx.commit().map_err(|e| e.to_string())?;
        // No history answer or sibling backfill may bring the rows back.
        // After the commit: a failed delete left the rows hidden for good.
        self.raise_history_floor(&floor_key, before_ms as u64);
        for id in &unsent {
            self.withdraw_unsent(id);
        }
        for file_id in &old_files {
            // A file offer still queued goes the same way (its message id is the file id).
            self.withdraw_unsent(file_id);
            self.delete_attachment_file(file_id);
        }
        Ok(())
    }

    /// Settings → Storage: drops only this device's copy of an attachment.
    /// The row stays, back to 'offered' (the bubble offers the download
    /// again); the peer is not told.
    pub(crate) fn remove_local_attachment(&mut self, file_id: &str) -> Result<(), String> {
        let conn = self.db.as_ref().ok_or("No DB")?;
        let changed = conn.execute(
            "UPDATE files SET status = 'offered', bytes_transferred = 0 WHERE file_id = ?1 AND direction != 'sent'",
            params![file_id],
        ).map_err(|e| e.to_string())?;
        // A sent row's copy is what the peers download from: kept.
        if changed == 0 {
            return Err(format!("Unknown or previously sent file_id: {}", file_id));
        }
        self.remove_attachment_copy(file_id);
        self.attachment_events.push(serde_json::json!({"type": "file_evicted", "file_id": file_id}).to_string());
        Ok(())
    }
}

/// A sticker as `SiblingEcho` bodies: one when it fits `STICKER_SYNC_MAX_BYTES`,
/// otherwise numbered parts the receiver puts back together.
pub(crate) fn sticker_echo_parts(id: &str, jxl: &[u8], origin: Option<String>) -> Vec<SiblingEchoBody> {
    if jxl.len() <= STICKER_SYNC_MAX_BYTES {
        return vec![SiblingEchoBody::Sticker { jxl: jxl.to_vec(), origin, id: id.to_string(), part: 0, parts: 0 }];
    }
    let chunks: Vec<&[u8]> = jxl.chunks(STICKER_SYNC_MAX_BYTES).collect();
    let parts = chunks.len() as u8; // MAX_STICKER_BYTES keeps this under STICKER_SYNC_MAX_PARTS
    chunks.into_iter().enumerate().map(|(i, c)| SiblingEchoBody::Sticker {
        jxl: c.to_vec(), origin: origin.clone(), id: id.to_string(), part: i as u8, parts,
    }).collect()
}

impl P2PCore {
    /// Keeps one part of a big sibling sticker. The whole file once every
    /// part is here, `Err` for a part that can never fit (final), `Ok(None)`
    /// while parts are missing.
    pub(crate) fn add_sticker_part(&mut self, id: &str, part: u8, parts: u8, data: Vec<u8>) -> Result<Option<Vec<u8>>, String> {
        let (part, parts) = (part as usize, parts as usize);
        let valid_id = id.len() == 64 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        if !valid_id || parts < 2 || parts > STICKER_SYNC_MAX_PARTS || part >= parts || data.len() > STICKER_SYNC_MAX_BYTES {
            return Err("bad sticker part".to_string());
        }
        if !self.sticker_parts.contains_key(id) && self.sticker_parts.len() >= STICKER_PARTS_MAX_PENDING {
            if let Some(oldest) = self.sticker_parts.iter().min_by_key(|(_, (at, _))| *at).map(|(k, _)| k.clone()) {
                self.sticker_parts.remove(&oldest);
            }
        }
        let entry = self.sticker_parts.entry(id.to_string()).or_insert_with(|| (current_time_ms(), vec![None; parts]));
        if entry.1.len() != parts {
            *entry = (current_time_ms(), vec![None; parts]);
        }
        entry.1[part] = Some(data);
        if entry.1.iter().any(Option::is_none) {
            return Ok(None);
        }
        let (_, pieces) = self.sticker_parts.remove(id).unwrap_or_default();
        let whole: Vec<u8> = pieces.into_iter().flatten().flatten().collect();
        if hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&whole)) != id {
            return Err("sticker parts do not match their id".to_string());
        }
        Ok(Some(whole))
    }
}

/// A folder name: trimmed, not empty, at most 64 characters.
fn sticker_folder_name(name: &str) -> Result<String, String> {
    let name = name.trim();
    if name.is_empty() {
        return Err("Folder name is empty".to_string());
    }
    Ok(name.chars().take(64).collect())
}

#[cfg(test)]
mod sticker_folder_tests {
    use super::*;

    #[test]
    fn folders_keep_stickers_and_drop_only_the_list() {
        let mut core = P2PCore::new();
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE stickers (id TEXT PRIMARY KEY, created_at INTEGER NOT NULL);
             INSERT INTO stickers VALUES ('a', 1), ('b', 2);
             CREATE TABLE sticker_folders (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, created_at INTEGER NOT NULL);
             CREATE TABLE sticker_folder_items (folder_id INTEGER NOT NULL, sticker_id TEXT NOT NULL, PRIMARY KEY (folder_id, sticker_id));",
        ).unwrap();
        core.db = Some(conn);
        assert!(core.create_sticker_folder("  ").is_err());
        let f = core.create_sticker_folder(" Cats ").unwrap();
        core.add_stickers_to_folder(f, &["a".into(), "a".into(), "gone".into()]).unwrap();
        core.add_stickers_to_folder(f, &["b".into()]).unwrap();
        core.remove_stickers_from_folder(f, &["b".into()]).unwrap();
        core.rename_sticker_folder(f, "Dogs").unwrap();
        let list: serde_json::Value = serde_json::from_str(&core.list_sticker_folders()).unwrap();
        assert_eq!(list, serde_json::json!([{ "id": f, "name": "Dogs", "stickers": ["a"] }]));
        core.delete_sticker_folder(f).unwrap();
        assert_eq!(core.list_sticker_folders(), "[]");
        let left: i64 = core.db.as_ref().unwrap().query_row("SELECT COUNT(*) FROM stickers", [], |r| r.get(0)).unwrap();
        assert_eq!(left, 2);
        assert!(core.add_stickers_to_folder(f, &["b".into()]).is_err());
    }
}
