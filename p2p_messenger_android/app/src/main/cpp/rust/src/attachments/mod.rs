//! File, photo, video and voice attachment transfer layer. Attachments were a later feature: the original file-transfer scope excluded
//! them, and this module extends it. Maximum size 4 GB.
//!
//! Model: the metadata (file name, size, MIME type, a fresh random AEAD key) travels over the normal ratchet-encrypted message channel
//! (see the `MessageContent::FileOffer` in file_transfer.rs). The fresh key is therefore protected end to end, and no separate key exchange
//! is needed. The actual bytes are requested and sent in fixed-size chunks (256 KiB) over a separate libp2p `request_response` protocol.
//! A 4 GB file cannot practically travel as ONE gossipsub message: gossipsub is designed for small, frequent messages, and the whole file
//! would have to fit in memory.
//!
//! Each chunk is encrypted SEPARATELY with the file's `file_key`, using a nonce derived from the chunk index
//! (see `nonce_from_chunk_index`, the same pattern as `nonce_from_message_number` in ratchet.rs). Stepping the Double Ratchet on every chunk
//! would be needlessly expensive (thousands of PQ-KEM steps), and it does not fit the design either: the ratchet gives per-message forward
//! secrecy, and here one "message" is already split into thousands of chunks. Integrity works at two levels: each chunk has its own AEAD tag,
//! verified as soon as the chunk arrives, and when the file is fully decrypted for display, the whole file is compared against its SHA-256
//! (see `decrypt_file_from_disk_with`).
//!
//! The `.enc` file on disk is simply the chunks appended in order, exactly as they were sent or received (encrypted). A device can therefore
//! re-serve a downloaded file to another requester without encrypting it again (see `read_chunk_from_disk_with`).

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

mod strip_metadata;
mod jxl_codec;
use strip_metadata::*;
pub use jxl_codec::*;

/// Plaintext chunk size. Encryption adds 16 bytes (the ChaCha20-Poly1305 AEAD tag), so a chunk on disk or on the wire is
/// `FILE_CHUNK_SIZE + 16` bytes (except the last chunk, which may be shorter).
pub const FILE_CHUNK_SIZE: usize = 256 * 1024;

/// What a peer's `FileOffer.chunk_size` may be. It sizes buffers and file
/// offsets on this device: too large is a multi-GiB allocation, too small is
/// billions of chunks for one file.
pub fn chunk_size_ok(chunk_size: usize) -> bool {
    (64 * 1024..=crate::server_proto::MAX_BLOB_CHUNK_BYTES - 16).contains(&chunk_size)
}

/// Chunk size for NEW files.
///
/// Currently 256 KiB, the same as the legacy size. This is a MEASURED decision, not a placeholder.
///
/// The theory was reasonable: each chunk costs one `request_response` round trip, so doubling the chunk size halves the number of round trips.
/// Measured with the same setup and the same files, after the fix below:
///   256 KiB -> median 199 KB/s (n=4, 121-291), no timeouts
///   512 KiB -> median 157 KB/s (n=3, 134-195), one of the four runs never finished
/// The reason: the round trip also doubles with the chunk (no gain), and on a timeout the WHOLE chunk is sent again. So a failure costs
/// twice as much, and the risk of never completing is real.
///
/// Note: this decision was first made with WRONG data. In that measurement the server computed the chunk position from its own constant
/// (`chunk_index * (256 KiB + 16)`), so every 512 KiB chunk was written to the wrong place. The file was corrupted, and the blob was rejected
/// forever. What was measured was a broken merge, not the chunk size. That bug was fixed first (the step now travels on the wire as
/// `BlobPut.chunk_size`), and then the measurement was repeated. The numbers above are AFTER the fix.
///
/// The mechanism (chunk size per file, carried in the offer, the `files.chunk_size` column, `BlobPut.chunk_size`) is kept on purpose:
/// it is correct, backward compatible, and retrying a different size now means changing a single constant. The ceiling is
/// `server_proto::MAX_BLOB_CHUNK_BYTES`.
pub const FILE_CHUNK_SIZE_V2: usize = 256 * 1024;

/// Compile-time guarantee: the chunk size the client picks can NEVER exceed the ceiling the server accepts. Once these two drifted apart,
/// transfers silently stalled with `TooLarge`.
const _: () = assert!(FILE_CHUNK_SIZE_V2 + 16 <= crate::server_proto::MAX_BLOB_CHUNK_BYTES);


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileChunkRequest {
    pub file_id: String,
    pub chunk_index: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FileChunkResponse {
    /// Encrypted chunk (ciphertext + 16-byte AEAD tag). The serving side reads it as-is from its own `.enc` file and sends it
    /// (see the module-level note).
    Chunk { #[serde(with = "serde_bytes")] data: Vec<u8> },
    /// `file_id` is unknown (never offered, or not complete), or `chunk_index` is out of range.
    NotFound,
    /// Rate limited: retry later from the same source.
    Busy,
}

/// Computes how many `FILE_CHUNK_SIZE` chunks a file of `total_size` bytes splits into. A 0-byte file gives 0. No special case is needed:
/// the caller's "0 chunks means done immediately" logic works naturally.
pub fn total_chunks_with(total_size: u64, chunk_size: usize) -> u32 {
    // `saturating_add`: callers must already validate `total_size` against `MAX_ATTACHMENT_SIZE` (see `receive_file_offer` in
    // file_transfer.rs and `prepare_and_send_file` in api.rs). This function also uses saturating addition as a defensive layer, so that a
    // `total_size` close to `u64::MAX` cannot overflow. A plain `+` would silently wrap in release builds.
    let cs = chunk_or_default(chunk_size) as u64;
    ((total_size.saturating_add(cs - 1)) / cs) as u32
}

/// Most entries in `FileOffer.chunk_hashes` (32 bytes each, so at most
/// 128 KiB in the offer). A full list for a 4 GiB file would be 16384 entries
/// (512 KiB), too large next to the preview for the server's deposit limit.
pub const MAX_CHUNK_HASHES: u32 = 4096;

/// How many chunks one `FileOffer.chunk_hashes` entry covers: 1 up to
/// `MAX_CHUNK_HASHES` chunks (1 GiB at 256 KiB), more for a larger file.
/// ponytail: a bad chunk of a file over 1 GiB is caught only when its whole
/// group (at most 4 chunks at 256 KiB) is in; a Merkle proof per chunk would
/// need proofs in every chunk response and on the server.
pub fn chunks_per_hash(total_chunks: u32) -> u32 {
    total_chunks.div_ceil(MAX_CHUNK_HASHES).max(1)
}

/// Byte length of `FileOffer.chunk_hashes` for a file of `total_chunks`.
pub fn chunk_hashes_len(total_chunks: u32) -> usize {
    total_chunks.div_ceil(chunks_per_hash(total_chunks)) as usize * 32
}

/// Plaintext length of chunk `index` of a `total_size` byte file: the chunk
/// size, less for the last chunk.
pub fn chunk_plain_len(total_size: u64, chunk_size: usize, index: u32) -> u64 {
    let cs = chunk_or_default(chunk_size) as u64;
    total_size.saturating_sub(index as u64 * cs).min(cs)
}

/// SHA-256 over the ciphertext of chunks `first..first + count` of a `.enc`
/// file, in order: one `FileOffer.chunk_hashes` entry. A missing chunk is an
/// error.
pub fn enc_range_hash(enc_path: &Path, first: u32, count: u32, chunk_size: usize) -> Result<[u8; 32], String> {
    // One open and one buffer for the whole range: a resume
    // hashed a multi-GB partial file with an open and an allocation per chunk.
    let stride = chunk_or_default(chunk_size) as u64 + 16;
    let mut f = File::open(enc_path).map_err(|_| "Chunk missing")?;
    f.seek(SeekFrom::Start(first as u64 * stride)).map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; stride as usize];
    let mut hasher = Sha256::new();
    for _ in 0..count {
        let n = read_full(&mut f, &mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("Chunk missing".to_string());
        }
        hasher.update(&buf[..n]);
        // A short chunk is the last one of the file.
        if (n as u64) < stride {
            break;
        }
    }
    Ok(hasher.finalize().into())
}

/// The `FileOffer.chunk_hashes` of a finished `.enc` file (the sender's side):
/// each chunk group's `enc_range_hash`, one after the other. The receiver
/// checks every chunk against it, so a group member who also holds the file
/// key cannot slip in chunks of its own.
pub fn chunk_hashes_of(enc_path: &Path, total_chunks: u32, chunk_size: usize) -> Result<Vec<u8>, String> {
    let per = chunks_per_hash(total_chunks);
    let mut out = Vec::with_capacity(chunk_hashes_len(total_chunks));
    let mut first = 0;
    while first < total_chunks {
        out.extend_from_slice(&enc_range_hash(enc_path, first, per.min(total_chunks - first), chunk_size)?);
        first += per;
    }
    Ok(out)
}

/// `chunk_size` 0 = the legacy fixed size (files from before per-file sizes).
fn chunk_or_default(chunk_size: usize) -> usize {
    if chunk_size == 0 { FILE_CHUNK_SIZE } else { chunk_size }
}

fn nonce_from_chunk_index(index: u32) -> Nonce {
    let mut bytes = [0u8; 12];
    bytes[8..12].copy_from_slice(&index.to_be_bytes());
    *Nonce::from_slice(&bytes)
}

fn read_full<R: Read>(r: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        let n = r.read(&mut buf[total..])?;
        if n == 0 {
            break;
        }
        total += n;
    }
    Ok(total)
}

/// Reads `source_path` (the file the user picked; Kotlin has already copied it to a local path, content:// URIs are not handled here) in
/// `FILE_CHUNK_SIZE` chunks, encrypts each chunk separately, and writes them to `dest_enc_path`. The WHOLE file is never in memory at once
/// (required for files up to 4 GB). Returns (total bytes, SHA-256 hex of the plaintext).
pub fn encrypt_file_to_disk_with(
    source_path: &Path,
    dest_enc_path: &Path,
    file_key: &[u8; 32],
    chunk_size: usize,
) -> Result<(u64, String), String> {
    let cipher = ChaCha20Poly1305::new_from_slice(file_key).map_err(|_| "Invalid file key")?;
    let mut src = File::open(source_path).map_err(|e| e.to_string())?;
    // A photo goes out without its EXIF/XMP: size and hash below are those
    // of the bytes that are sent. A JPEG/PNG/JPEG XL the scanner cannot follow
    // is refused, not sent with its metadata.
    let mut magic = [0u8; 8];
    let got = read_full(&mut src, &mut magic).map_err(|e| e.to_string())?;
    const DOUBT: &str = "Photo metadata could not be removed; file not sent";
    // The patched start of the file and how many bytes of it it replaces.
    let mut head = Vec::new();
    let mut skip: u64 = 0;
    let (ranges, orientation) = if got >= 2 && magic[..2] == [0xFF, 0xD8] {
        jpeg_metadata_ranges(&mut src).ok_or(DOUBT)?
    } else if got == 8 && magic == *b"\x89PNG\r\n\x1a\n" {
        (png_metadata_ranges(&mut src).ok_or(DOUBT)?, None)
    } else if got >= 2 && (magic[..2] == [0xFF, 0x0A] || (got == 8 && magic == *b"\0\0\0\x0CJXL ")) {
        (jxl_metadata_ranges(&mut src).ok_or(DOUBT)?, None)
    } else if got == 8 && magic[..4] == *b"RIFF" {
        let (ranges, patched) = webp_metadata_ranges(&mut src).ok_or(DOUBT)?;
        skip = patched.len() as u64;
        head = patched;
        (ranges, None)
    } else {
        // HEIC/AVIF (ISO-BMFF) and TIFF keep their EXIF/XMP here: their
        // metadata sits behind item offsets (`iloc`) or IFD offsets that a
        // byte cut would break, and a broken photo is worse. Only a
        // re-encode by the client removes it.
        (Vec::new(), None)
    };
    // The one tag that goes back in, right after the start-of-image marker.
    if let Some(orientation) = orientation {
        head.extend_from_slice(&[0xFF, 0xD8]);
        head.extend_from_slice(&orientation_segment(orientation));
        skip = 2;
    }
    src.seek(SeekFrom::Start(skip)).map_err(|e| e.to_string())?;
    let pos = skip;
    let mut src = std::io::Cursor::new(head).chain(SkipRanges { file: src, pos, ranges: ranges.into() });
    let mut dest = File::create(dest_enc_path).map_err(|e| e.to_string())?;
    let mut hasher = Sha256::new();
    let chunk_size = chunk_or_default(chunk_size);
    let mut buf = vec![0u8; chunk_size];
    let mut total: u64 = 0;
    let mut chunk_index: u32 = 0;
    loop {
        let n = read_full(&mut src, &mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        let nonce = nonce_from_chunk_index(chunk_index);
        let ciphertext = cipher.encrypt(&nonce, &buf[..n]).map_err(|_| "Chunk encryption failed")?;
        dest.write_all(&ciphertext).map_err(|e| e.to_string())?;
        total += n as u64;
        chunk_index = chunk_index.checked_add(1).ok_or("File too large")?;
        if n < chunk_size {
            break;
        }
    }
    dest.sync_data().map_err(|e| e.to_string())?;
    Ok((total, hex::encode(hasher.finalize())))
}

/// Decrypts the file at `src_enc_path` (chunk by chunk) and writes the plaintext to `dest_plain_path`. Again bounded memory, one chunk at a time.
/// The SHA-256 computed at the end is compared with `expected_sha256_hex`. A mismatch returns an error. This is the ONLY whole-file integrity
/// check between the hash claimed in the `FileOffer` and the actual content. Per-chunk AEAD tags already verify each chunk separately, but a
/// truncation such as a missing final chunk is caught here.
pub fn decrypt_file_from_disk_with(
    src_enc_path: &Path,
    dest_plain_path: &Path,
    file_key: &[u8; 32],
    expected_sha256_hex: &str,
    chunk_size: usize,
) -> Result<(), String> {
    let chunk_size = chunk_or_default(chunk_size);
    let cipher = ChaCha20Poly1305::new_from_slice(file_key).map_err(|_| "Invalid file key")?;
    let mut src = File::open(src_enc_path).map_err(|e| e.to_string())?;
    let mut dest = File::create(dest_plain_path).map_err(|e| e.to_string())?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; chunk_size + 16];
    let mut chunk_index: u32 = 0;
    loop {
        let n = read_full(&mut src, &mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        let nonce = nonce_from_chunk_index(chunk_index);
        let plaintext = cipher.decrypt(&nonce, &buf[..n]).map_err(|_| format!("Chunk {} decryption failed", chunk_index))?;
        hasher.update(&plaintext);
        dest.write_all(&plaintext).map_err(|e| e.to_string())?;
        chunk_index = chunk_index.checked_add(1).ok_or("File too large")?;
        if n < buf.len() {
            break;
        }
    }
    let actual = hex::encode(hasher.finalize());
    // Offers carry the hex as the sender wrote it; the download check ignores case too.
    if !actual.eq_ignore_ascii_case(expected_sha256_hex) {
        let _ = std::fs::remove_file(dest_plain_path);
        return Err(format!("SHA-256 mismatch: expected {}, got {}", expected_sha256_hex, actual));
    }
    Ok(())
}

/// The serving side (this device sent a file, or downloaded it completely and is re-serving it) reads one chunk from its `.enc` file AS-IS
/// (still encrypted). No re-encryption is needed: the disk format is already the same as the wire format (see the module-level note).
pub fn read_chunk_from_disk_with(enc_path: &Path, chunk_index: u32, chunk_size: usize) -> Result<Option<Vec<u8>>, String> {
    let chunk_size = chunk_or_default(chunk_size);
    let mut f = match File::open(enc_path) {
        Ok(f) => f,
        Err(_) => return Ok(None),
    };
    let offset = chunk_index as u64 * (chunk_size as u64 + 16);
    if f.seek(SeekFrom::Start(offset)).is_err() {
        return Ok(None);
    }
    let mut buf = vec![0u8; chunk_size + 16];
    let n = read_full(&mut f, &mut buf).map_err(|e| e.to_string())?;
    if n == 0 {
        return Ok(None);
    }
    buf.truncate(n);
    Ok(Some(buf))
}

/// One chunk of a `.enc` file, decrypted (see `handle_chunk_response` in file_transfer.rs: the whole-file hash check of a download).
pub fn read_plain_chunk_with(enc_path: &Path, chunk_index: u32, file_key: &[u8; 32], chunk_size: usize) -> Result<Vec<u8>, String> {
    let data = read_chunk_from_disk_with(enc_path, chunk_index, chunk_size)?.ok_or("Chunk missing")?;
    let cipher = ChaCha20Poly1305::new_from_slice(file_key).map_err(|_| "Invalid file key")?;
    cipher.decrypt(&nonce_from_chunk_index(chunk_index), data.as_slice()).map_err(|_| format!("Chunk {} decryption failed", chunk_index))
}

/// The failure kinds of `write_verified_chunk_at_with`. The caller (see `handle_chunk_response` in file_transfer.rs) needs this distinction to
/// choose its recovery strategy: an AEAD failure, or a disk write failure?
#[derive(Debug)]
pub enum ChunkAppendError {
    /// AEAD authentication FAILED: the chunk is corrupt or forged. Decryption runs BEFORE anything is written to disk, so NOTHING was written
    /// to the `.enc` file. The caller can safely request the SAME `chunk_index` from ANOTHER source (no need to restart the download). This stops
    /// a single corrupt or malicious source from killing the whole download.
    Auth(String),
    /// File system write error: the `.enc` file may be PARTIALLY written and cannot be guaranteed consistent any more. The download must restart.
    Io(String),
}

impl std::fmt::Display for ChunkAppendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChunkAppendError::Auth(s) | ChunkAppendError::Io(s) => write!(f, "{}", s),
        }
    }
}

/// Verifies an incoming chunk (AEAD tag) and writes it at its OWN position, instead of appending it:
/// `chunk_index * (FILE_CHUNK_SIZE + 16)`.
///
/// Why this is needed: appending required chunks to arrive in STRICT order. Only one chunk could be in flight at a time, so the transfer rate
/// was limited to `chunk_size / round_trip_time`, regardless of bandwidth. Pipelining (several chunks in flight at once) is only possible
/// with position-based writes.
///
/// This is safe because the `.enc` format has a FIXED STEP: `read_chunk_from_disk_with` already reads with exactly this arithmetic. The last
/// chunk may be shorter, but it has the highest index, so it stays at the end of the file.
///
/// CRITICAL PROPERTY, KEPT: the AEAD check runs BEFORE the write. On an `Auth` error nothing is written to disk, so the caller can safely
/// request the same chunk from another source (see `ChunkAppendError`).
pub fn write_verified_chunk_at_with(dest_enc_path: &Path, chunk_index: u32, ciphertext: &[u8], file_key: &[u8; 32], chunk_size: usize) -> Result<usize, ChunkAppendError> {
    let chunk_size = chunk_or_default(chunk_size);
    // A longer chunk would overwrite the slot of the next chunk.
    if ciphertext.len() > chunk_size + 16 {
        return Err(ChunkAppendError::Auth(format!("Chunk {} is longer than the file's chunk size", chunk_index)));
    }
    let cipher = ChaCha20Poly1305::new_from_slice(file_key)
        .map_err(|_| ChunkAppendError::Auth("Invalid file key".to_string()))?;
    let nonce = nonce_from_chunk_index(chunk_index);
    let plaintext = cipher.decrypt(&nonce, ciphertext)
        .map_err(|_| ChunkAppendError::Auth(format!("Chunk {} authentication failed", chunk_index)))?;
    let plaintext_len = plaintext.len();
    let mut f = OpenOptions::new().create(true).write(true).open(dest_enc_path)
        .map_err(|e| ChunkAppendError::Io(e.to_string()))?;
    let offset = chunk_index as u64 * (chunk_size as u64 + 16);
    f.seek(SeekFrom::Start(offset)).map_err(|e| ChunkAppendError::Io(e.to_string()))?;
    f.write_all(ciphertext).map_err(|e| ChunkAppendError::Io(e.to_string()))?;
    // The caller records the chunk as received only after it is on disk. Otherwise a power loss would leave a hole in a download marked done.
    f.sync_data().map_err(|e| ChunkAppendError::Io(e.to_string()))?;
    Ok(plaintext_len)
}

#[cfg(test)]
mod tests;
