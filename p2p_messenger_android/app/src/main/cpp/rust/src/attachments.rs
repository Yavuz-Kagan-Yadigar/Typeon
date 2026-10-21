//! Dosya/foto/video/ses eki taşıma katmanı — spec dışı, kullanıcı
//! tarafından istenen bir ek özellik (spec bölüm 6 "dosya transferi v0.1/
//! v0.2 kapsamı DIŞINDA" notunu genişletir; azami 4GB).
//!
//! Model: meta veri (dosya adı, boyutu, MIME, taze rastgele bir AEAD
//! anahtarı) normal ratchet-şifreli mesaj kanalıyla taşınır (bkz. lib.rs
//! `MessageContent::FileOffer`) — bu, taze anahtarın da uçtan uca
//! korunmasını sağlar, ayrı bir anahtar değişimi icat edilmez. Gerçek bayt
//! içeriği BURADAKİ ayrı bir libp2p `request_response` protokolü ile,
//! sabit boyutlu (256 KiB) parçalar (chunk) hâlinde istenir/gönderilir —
//! 4GB'a kadar bir dosyayı TEK bir gossipsub mesajıyla taşımak pratik
//! değil (gossipsub küçük/sık mesajlar için tasarlanmış, bütün dosyanın
//! belleğe sığması gerekirdi).
//!
//! Her parça, dosyaya özel `file_key` ile AYRI AYRI şifrelenir (parça
//! indeksinden türetilen bir nonce'la, bkz. `nonce_from_chunk_index` —
//! `ratchet.rs`'teki `nonce_from_message_number` ile aynı desen). Double
//! Ratchet'in HER parçada bir adım atması hem gereksiz maliyetli olurdu
//! (binlerce PQ-KEM adımı) hem de tasarım amacına aykırı (mesaj bazlı
//! ileri gizlilik için; burada tek bir "mesaj" zaten binlerce parçaya
//! bölünüyor). Bütünlük iki katmanda sağlanır: her parçanın kendi AEAD
//! etiketi (parça seviyesinde, alınır alınmaz doğrulanır) ve dosya
//! tamamen çözülüp görüntülenmek istendiğinde tüm-dosya SHA-256
//! karşılaştırması (bkz. `decrypt_file_from_disk_with`).
//!
//! Diskte saklanan `.enc` dosyası, parçaların OLDUĞU GİBİ (şifreli, ağdan
//! geldiği/gideceği biçimde) art arda eklenmesinden oluşur — bu, bir
//! cihazın indirdiği bir dosyayı BAŞKA bir isteyene tekrar şifrelemeden
//! servis edebilmesini sağlar (bkz. `read_chunk_from_disk_with`).

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

/// Düz metin parça boyutu — şifrelendiğinde +16 bayt (ChaCha20-Poly1305
/// AEAD etiketi) eklenir, diskte/ağda bir parça `FILE_CHUNK_SIZE + 16`
/// bayttır (son parça hariç, o daha kısa olabilir).
pub const FILE_CHUNK_SIZE: usize = 256 * 1024;

/// What a peer's `FileOffer.chunk_size` may be. It sizes buffers and file
/// offsets on this device: too large is a multi-GiB allocation, too small is
/// billions of chunks for one file.
pub fn chunk_size_ok(chunk_size: usize) -> bool {
    (64 * 1024..=crate::server_proto::MAX_BLOB_CHUNK_BYTES - 16).contains(&chunk_size)
}

/// YENI dosyalar icin parca boyutu.
///
/// SU AN 256 KiB — miras boyutla ayni. Yer tutucu degil, OLCULMUS bir karar.
///
/// Teori makuldu: her parca bir `request_response` gidis-donusu, parcayi
/// ikiye katlamak gidis-donus sayisini yariya indirir. Ayni duzenekte,
/// donusumlu, ayni dosyalarla olculdu:
///   256 KiB -> medyan 199 KB/s (n=4, 121-291), zaman asimi YOK
///   512 KiB -> medyan 157 KB/s (n=3, 134-195), dort turun BIRI hic bitmedi
/// Sebep: gidis-donus de parcayla birlikte iki katina cikiyor (kazanc yok),
/// ustune bir zaman asiminda KOCA parca bastan gidiyor — yani basarisizligin
/// maliyeti iki kati ve tamamlanamama riski gercek.
///
/// NOT: bu karar bir kez YANLIS veriyle verilmisti. O olcumde sunucu, parca
/// konumunu kendi sabitinden hesapliyordu (`chunk_index * (256 KiB + 16)`),
/// yani 512 KiB'lik her parca yanlis yere yaziliyor, dosya bozuluyor ve
/// blob sonsuza dek reddediliyordu; olculen sey parca boyutu degil bozuk
/// birlestirmeydi. Once o hata duzeltildi (adim artik `BlobPut.chunk_size`
/// ile telde tasiniyor), sonra olcum tekrarlandi. Yukaridaki rakamlar
/// duzeltme SONRASI.
///
/// Mekanizma (parca boyutunun DOSYA BASINA olmasi, teklifle tasinmasi,
/// `files.chunk_size` kolonu, `BlobPut.chunk_size`) KASITLI olarak duruyor:
/// dogru, geriye donuk uyumlu, ve boyutu yeniden denemek artik tek sabit
/// degistirmek. Tavan: `server_proto::MAX_BLOB_CHUNK_BYTES`.
pub const FILE_CHUNK_SIZE_V2: usize = 256 * 1024;

/// Derleme zamanı güvencesi: istemcinin seçtiği parça boyutu, sunucunun
/// kabul ettiği tavanı ASLA aşamaz. Bu ikisi bir kez ayrıştı ve sonuç,
/// aktarımın `TooLarge` ile sessizce hiç ilerlememesiydi.
const _: () = assert!(FILE_CHUNK_SIZE_V2 + 16 <= crate::server_proto::MAX_BLOB_CHUNK_BYTES);


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileChunkRequest {
    pub file_id: String,
    pub chunk_index: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FileChunkResponse {
    /// Şifreli parça (ciphertext + 16 baytlık AEAD etiketi) — sunan taraf
    /// bunu kendi diskindeki `.enc` dosyasından OLDUĞU GİBİ okuyup
    /// gönderir (bkz. modül başı notu).
    Chunk { #[serde(with = "serde_bytes")] data: Vec<u8> },
    /// `file_id` bilinmiyor (hiç sunulmuyor/tamamlanmamış) veya
    /// `chunk_index` aralık dışı.
    NotFound,
    /// Rate limited: retry later from the same source.
    Busy,
}

/// `total_size` baytlık bir dosyanın kaç `FILE_CHUNK_SIZE`'lık parçaya
/// böleceğini hesaplar (0 baytlık dosya için 0 döner — özel durum
/// gerektirmez, çağıran tarafın "0 parça = hemen tamamlandı" mantığı
/// doğal olarak çalışır).
pub fn total_chunks_with(total_size: u64, chunk_size: usize) -> u32 {
    // `saturating_add`: `total_size` çağıranlar tarafından zaten
    // `MAX_ATTACHMENT_SIZE`'a karşı doğrulanmalı (bkz. lib.rs
    // `receive_file_offer`/`prepare_and_send_file`), ama bu fonksiyon
    // kendi başına da (savunma katmanı) `total_size` neredeyse `u64::MAX`
    // olsa bile taşmasın diye doygun toplama kullanıyor — çıplak `+`
    // release'de sessizce sarardı.
    let cs = chunk_or_default(chunk_size) as u64;
    ((total_size.saturating_add(cs - 1)) / cs) as u32
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

/// The byte ranges of the metadata segments of a JPEG file: APP1 (EXIF with
/// the GPS position, XMP) and APP13 (Photoshop/IPTC). The image data, JFIF
/// and the ICC profile (APP2) are outside them. With them the EXIF
/// orientation of the photo, if it is not the upright one: the caller puts
/// that one tag back (`orientation_segment`), or a photo taken rotated is
/// shown as the sensor stored it.
/// None for a file that is not a JPEG and on any doubt about its structure:
/// the caller then refuses to send it (fail closed, the EXIF may hold GPS).
fn jpeg_metadata_ranges(file: &mut File) -> Option<(Vec<(u64, u64)>, Option<u8>)> {
    {
        let len = file.metadata().ok()?.len();
        let mut head = [0u8; 4];
        file.seek(SeekFrom::Start(0)).ok()?;
        if read_full(file, &mut head[..2]).ok()? != 2 || head[..2] != [0xFF, 0xD8] {
            return None;
        }
        let mut ranges = Vec::new();
        let mut orientation = None;
        let mut at: u64 = 2;
        // ponytail: 4096 segments; a real file has a few dozen.
        for _ in 0..4096 {
            file.seek(SeekFrom::Start(at)).ok()?;
            if read_full(file, &mut head).ok()? != 4 || head[0] != 0xFF {
                return None;
            }
            let marker = head[1];
            // Start of scan: the header is over, the rest is image data up to
            // the end-of-image marker. What follows it (a motion-photo video,
            // a second "multi-picture" JPEG with its own EXIF) is dropped.
            if marker == 0xDA {
                let eoi = jpeg_image_end(file, at)?;
                if eoi < len {
                    ranges.push((eoi, len));
                }
                return Some((ranges, orientation));
            }
            // Only segments that carry a length are expected before the scan.
            let known = matches!(marker, 0xC0..=0xCF | 0xDB..=0xDF | 0xE0..=0xEF | 0xFE) && marker != 0xC8;
            let size = u16::from_be_bytes([head[2], head[3]]) as u64;
            let end = at.checked_add(2 + size)?;
            if !known || size < 2 || end > len {
                return None;
            }
            if marker == 0xE1 || marker == 0xED {
                ranges.push((at, end));
            }
            // The multi-picture index points into the dropped trailer.
            if marker == 0xE2 && size >= 6 {
                let mut tag = [0u8; 4];
                if read_full(file, &mut tag).ok()? == 4 && &tag == b"MPF\0" {
                    ranges.push((at, end));
                }
                file.seek(SeekFrom::Start(at + 4)).ok()?;
            }
            if marker == 0xE1 && orientation.is_none() {
                let mut body = vec![0u8; size as usize - 2];
                if read_full(file, &mut body).ok()? != body.len() {
                    return None;
                }
                orientation = exif_orientation(&body);
            }
            at = end;
        }
        None
    }
}

/// The offset just past the end-of-image marker, scanning from the start-of-
/// scan segment at `sos`: entropy-coded data, and between progressive scans
/// further marker segments with a length.
fn jpeg_image_end(file: &mut File, sos: u64) -> Option<u64> {
    let mut reader = std::io::BufReader::with_capacity(1 << 16, &mut *file);
    reader.seek(SeekFrom::Start(sos + 1)).ok()?;
    let mut at = sos + 1;
    let mut byte = [0u8; 1];
    let mut next = |reader: &mut std::io::BufReader<&mut File>, at: &mut u64| -> Option<u8> {
        reader.read_exact(&mut byte).ok()?;
        *at += 1;
        Some(byte[0])
    };
    // At a marker (0xFF already read): its code, then the segment if it has one.
    let mut marker_segment = true;
    loop {
        if marker_segment {
            let code = next(&mut reader, &mut at)?;
            let mut len = [0u8; 2];
            len[0] = next(&mut reader, &mut at)?;
            len[1] = next(&mut reader, &mut at)?;
            let size = u16::from_be_bytes(len) as i64;
            if size < 2 || code == 0xD9 {
                return None;
            }
            reader.seek_relative(size - 2).ok()?;
            at += size as u64 - 2;
            marker_segment = false;
        }
        if next(&mut reader, &mut at)? != 0xFF {
            continue;
        }
        let mut code = next(&mut reader, &mut at)?;
        while code == 0xFF {
            code = next(&mut reader, &mut at)?;
        }
        match code {
            0x00 | 0xD0..=0xD7 => {}
            0xD9 => return Some(at),
            _ => {
                // Back over the code: the segment branch reads it again.
                reader.seek_relative(-2).ok()?;
                at -= 2;
                next(&mut reader, &mut at)?;
                marker_segment = true;
            }
        }
    }
}

/// PNG chunks that carry text, time or EXIF (`eXIf` can hold the GPS
/// position), and anything after `IEND`. Image chunks and the colour profile
/// stay. None for a file that is not a PNG, and on any doubt.
fn png_metadata_ranges(file: &mut File) -> Option<Vec<(u64, u64)>> {
    {
        let len = file.metadata().ok()?.len();
        let mut head = [0u8; 8];
        file.seek(SeekFrom::Start(0)).ok()?;
        if read_full(file, &mut head).ok()? != 8 || head != *b"\x89PNG\r\n\x1a\n" {
            return None;
        }
        let mut ranges = Vec::new();
        let mut at = 8u64;
        // ponytail: 1 << 16 chunks; real files have tens (APNG: frames x2).
        for _ in 0..1 << 16 {
            file.seek(SeekFrom::Start(at)).ok()?;
            if read_full(file, &mut head).ok()? != 8 {
                return None;
            }
            let end = at.checked_add(12 + u32::from_be_bytes(head[..4].try_into().ok()?) as u64)?;
            if end > len {
                return None;
            }
            match &head[4..8] {
                b"eXIf" | b"tEXt" | b"iTXt" | b"zTXt" | b"tIME" => ranges.push((at, end)),
                b"IEND" => {
                    if end < len {
                        ranges.push((end, len));
                    }
                    return Some(ranges);
                }
                _ => {}
            }
            at = end;
        }
        None
    }
}

/// The orientation (2..=8, not the upright 1) in the body of an EXIF APP1
/// segment: tag 0x0112 of the first image directory.
fn exif_orientation(body: &[u8]) -> Option<u8> {
    let tiff = body.strip_prefix(b"Exif\0\0")?;
    let big_endian = match tiff.get(..4)? {
        b"MM\0*" => true,
        b"II*\0" => false,
        _ => return None,
    };
    let u16_at = |at: usize| -> Option<u16> {
        let b: [u8; 2] = tiff.get(at..at.checked_add(2)?)?.try_into().ok()?;
        Some(if big_endian { u16::from_be_bytes(b) } else { u16::from_le_bytes(b) })
    };
    let dir_bytes: [u8; 4] = tiff.get(4..8)?.try_into().ok()?;
    let dir = (if big_endian { u32::from_be_bytes(dir_bytes) } else { u32::from_le_bytes(dir_bytes) }) as usize;
    for i in 0..u16_at(dir)? as usize {
        let entry = dir.checked_add(2 + 12 * i)?;
        if u16_at(entry)? == 0x0112 {
            let value = u16_at(entry.checked_add(8)?)?;
            return (2..=8).contains(&value).then_some(value as u8);
        }
    }
    None
}

/// An EXIF APP1 segment that holds the orientation and nothing else.
fn orientation_segment(orientation: u8) -> [u8; 36] {
    let mut segment = *b"\xFF\xE1\0\x22Exif\0\0MM\0*\0\0\0\x08\0\x01\x01\x12\0\x03\0\0\0\x01\0\0\0\0\0\0\0\0";
    segment[29] = orientation;
    segment
}

/// Reads a file without the given ranges (sorted, not overlapping).
struct SkipRanges {
    file: File,
    pos: u64,
    ranges: std::collections::VecDeque<(u64, u64)>,
}

impl Read for SkipRanges {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut max = buf.len();
        while let Some(&(start, end)) = self.ranges.front() {
            if self.pos < start {
                max = max.min((start - self.pos) as usize);
                break;
            }
            self.file.seek(SeekFrom::Start(end))?;
            self.pos = end;
            self.ranges.pop_front();
        }
        let n = self.file.read(&mut buf[..max])?;
        self.pos += n as u64;
        Ok(n)
    }
}

/// `source_path`'i (kullanıcının seçtiği dosya — Kotlin tarafından zaten
/// yerel bir yola kopyalanmış olmalı, content:// URI burada işlenmez)
/// `FILE_CHUNK_SIZE`'lık parçalar hâlinde OKUYUP her parçayı ayrı ayrı
/// şifreleyerek `dest_enc_path`'e yazar — dosyanın TAMAMI hiçbir anda
/// bellekte olmaz (4GB'a kadar bir dosya için bu şart). Dönüş: (toplam
/// bayt, plaintext SHA-256 hex).
pub fn encrypt_file_to_disk_with(
    source_path: &Path,
    dest_enc_path: &Path,
    file_key: &[u8; 32],
    chunk_size: usize,
) -> Result<(u64, String), String> {
    let cipher = ChaCha20Poly1305::new_from_slice(file_key).map_err(|_| "Invalid file key")?;
    let mut src = File::open(source_path).map_err(|e| e.to_string())?;
    // A photo goes out without its EXIF/XMP: size and hash below are those
    // of the bytes that are sent. A JPEG/PNG the scanner cannot follow is
    // refused, not sent with its metadata.
    let mut magic = [0u8; 8];
    let got = read_full(&mut src, &mut magic).map_err(|e| e.to_string())?;
    const DOUBT: &str = "Photo metadata could not be removed; file not sent";
    let (ranges, orientation) = if got >= 2 && magic[..2] == [0xFF, 0xD8] {
        jpeg_metadata_ranges(&mut src).ok_or(DOUBT)?
    } else if got == 8 && magic == *b"\x89PNG\r\n\x1a\n" {
        (png_metadata_ranges(&mut src).ok_or(DOUBT)?, None)
    } else {
        (Vec::new(), None)
    };
    src.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    // The one tag that goes back in, right after the start-of-image marker.
    let mut head = Vec::new();
    if let Some(orientation) = orientation {
        head.extend_from_slice(&[0xFF, 0xD8]);
        head.extend_from_slice(&orientation_segment(orientation));
        src.seek(SeekFrom::Start(2)).map_err(|e| e.to_string())?;
    }
    let pos = if head.is_empty() { 0 } else { 2 };
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

/// `src_enc_path`'teki (parça parça şifreli) dosyayı çözüp
/// `dest_plain_path`'e yazar — yine bounded-memory, bir seferde bir parça.
/// Sonunda hesaplanan SHA-256, `expected_sha256_hex` ile eşleşmezse hata
/// döner — bu, `FileOffer`'daki iddia edilen hash ile fiili içerik
/// arasındaki TEK tam-dosya seviyeli bütünlük kontrolüdür (parça
/// seviyesindeki AEAD etiketi zaten her parçayı ayrı ayrı doğrular, ama
/// örn. sondan eksik parça gibi bir kesilme burada yakalanır).
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
    if actual != expected_sha256_hex {
        let _ = std::fs::remove_file(dest_plain_path);
        return Err(format!("SHA-256 mismatch: expected {}, got {}", expected_sha256_hex, actual));
    }
    Ok(())
}

/// Sunan tarafın (bu cihaz bir dosyayı gönderdi VEYA tamamen indirip
/// re-serve ediyor) tek bir parçayı `.enc` dosyasından OLDUĞU GİBİ
/// (şifreli) okuması — tekrar şifrelemeye gerek yok, disk formatı zaten
/// ağ formatıyla aynı (bkz. modül başı notu).
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

/// One chunk of a `.enc` file, decrypted (bkz. lib.rs `handle_chunk_response`:
/// the whole-file hash of a download).
pub fn read_plain_chunk_with(enc_path: &Path, chunk_index: u32, file_key: &[u8; 32], chunk_size: usize) -> Result<Vec<u8>, String> {
    let data = read_chunk_from_disk_with(enc_path, chunk_index, chunk_size)?.ok_or("Chunk missing")?;
    let cipher = ChaCha20Poly1305::new_from_slice(file_key).map_err(|_| "Invalid file key")?;
    cipher.decrypt(&nonce_from_chunk_index(chunk_index), data.as_slice()).map_err(|_| format!("Chunk {} decryption failed", chunk_index))
}

/// `write_verified_chunk_at_with`'in başarısızlık türü — çağıranın (bkz. lib.rs
/// `handle_chunk_response`) kurtarma stratejisini seçebilmesi için KRİTİK
/// ayrım (dış AI incelemesi düzeltmesi): AEAD hatası mı yoksa disk yazma
/// hatası mı?
#[derive(Debug)]
pub enum ChunkAppendError {
    /// AEAD kimlik doğrulaması BAŞARISIZ — parça bozuk/sahte, AMA çözme
    /// diske yazmadan ÖNCE yapıldığından `.enc` dosyasına HİÇBİR ŞEY
    /// yazılmadı. Çağıran, AYNI `chunk_index`'i güvenle BAŞKA bir kaynaktan
    /// yeniden isteyebilir (indirmeyi baştan başlatmaya gerek yok). Bu, tek
    /// bir bozuk/kötü niyetli kaynağın tüm indirmeyi öldürmesini önler.
    Auth(String),
    /// Dosya sistemi yazma hatası — `.enc` KISMEN yazılmış olabilir ve artık
    /// tutarlı olduğu GARANTİ EDİLEMEZ; indirme baştan başlatılmalıdır.
    Io(String),
}

impl std::fmt::Display for ChunkAppendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChunkAppendError::Auth(s) | ChunkAppendError::Io(s) => write!(f, "{}", s),
        }
    }
}

/// Bir gelen parçayı doğrular (AEAD etiketi) ve sona EKLEMEK
/// yerine kendi KONUMUNA yazar: `chunk_index * (FILE_CHUNK_SIZE + 16)`.
///
/// Neden gerekli: sona ekleme, parçaların KESİN OLARAK sırayla gelmesini
/// şart koşuyordu — yani aynı anda tek bir parça havada olabiliyordu ve
/// aktarım hızı `parça_boyutu / gidiş-dönüş süresi` ile sınırlı kalıyordu
/// (bant genişliğinden bağımsız olarak). Boru hattı (aynı anda birden çok
/// parça) ancak konum tabanlı yazmayla mümkün.
///
/// Bu güvenli, çünkü `.enc` formatı SABİT ADIMLI: `read_chunk_from_disk_with`
/// zaten tam bu aritmetikle okuyor. Son parça daha kısa olabilir ama en
/// yüksek indeks olduğundan dosyanın sonunda kalır.
///
/// KRİTİK ÖZELLİK KORUNUYOR: AEAD doğrulaması yazmadan ÖNCE yapılır, yani
/// `Auth` hatasında diske HİÇBİR ŞEY yazılmaz — çağıran aynı parçayı başka
/// bir kaynaktan güvenle yeniden isteyebilir (bkz. `ChunkAppendError`).
pub fn write_verified_chunk_at_with(dest_enc_path: &Path, chunk_index: u32, ciphertext: &[u8], file_key: &[u8; 32], chunk_size: usize) -> Result<usize, ChunkAppendError> {
    let chunk_size = chunk_or_default(chunk_size);
    // A longer chunk would be written over the next chunk's slot.
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
    // The caller records the chunk as received: it must be on disk first,
    // or a power loss leaves a hole in a download marked done.
    f.sync_data().map_err(|e| ChunkAppendError::Io(e.to_string()))?;
    Ok(plaintext_len)
}

/// Largest image the JPEG XL paths take, in pixels: 64 MP is 256 MB as RGBA,
/// and a received file names its own size.
pub const MAX_IMAGE_PIXELS: u64 = 24_000_000;

/// A "hi-res" image attachment: lossless JPEG XL of 8-bit RGBA pixels, row
/// after row, not premultiplied. With `has_alpha` false the alpha bytes are
/// dropped first, in place: `rgba` is the caller's buffer and is changed.
pub fn encode_jxl_lossless(rgba: &mut [u8], width: u32, height: u32, has_alpha: bool, out: &Path) -> Result<(), String> {
    std::fs::write(out, jxl_codestream(rgba, width, height, has_alpha)?).map_err(|e| e.to_string())
}

fn jxl_codestream(rgba: &mut [u8], width: u32, height: u32, has_alpha: bool) -> Result<Vec<u8>, String> {
    use zune_core::{bit_depth::BitDepth, colorspace::ColorSpace, options::EncoderOptions};
    let pixels = width as u64 * height as u64;
    if width < 2 || height < 2 || pixels > MAX_IMAGE_PIXELS || rgba.len() as u64 != pixels * 4 {
        return Err("Bad image size".to_string());
    }
    let pixels = pixels as usize;
    let (data, colorspace): (&[u8], ColorSpace) = if has_alpha {
        (&*rgba, ColorSpace::RGBA)
    } else {
        for i in 0..pixels {
            rgba.copy_within(i * 4..i * 4 + 3, i * 3);
        }
        (&rgba[..pixels * 3], ColorSpace::RGB)
    };
    let options = EncoderOptions::new(width as usize, height as usize, colorspace, BitDepth::Eight);
    let mut encoded = Vec::new();
    zune_jpegxl::JxlSimpleEncoder::new(data, options)
        .encode(&mut encoded)
        .map_err(|e| format!("JPEG XL: {e:?}"))?;
    Ok(encoded)
}

/// Most frames an animated image keeps; all frames together stay within
/// `MAX_IMAGE_PIXELS` too.
pub const MAX_ANIMATION_FRAMES: usize = 300;

/// LSB-first bit writer: the JPEG XL codestream and GIF's LZW codes both
/// pack bits this way.
#[derive(Default)]
struct Bits { out: Vec<u8>, acc: u64, n: u32 }

impl Bits {
    fn put(&mut self, nbits: u32, value: u64) {
        self.acc |= value << self.n;
        self.n += nbits;
        while self.n >= 8 {
            self.out.push(self.acc as u8);
            self.acc >>= 8;
            self.n -= 8;
        }
    }
    fn pad(&mut self) {
        if self.n > 0 {
            self.out.push(self.acc as u8);
            (self.acc, self.n) = (0, 0);
        }
    }
}

/// The image header zune-jpegxl writes (8-bit sRGB, RGB or RGBA), with
/// `animated` adding an animation of 1000 ticks per second, looping forever.
fn jxl_image_header(width: u32, height: u32, alpha: bool, animated: bool) -> Vec<u8> {
    let mut b = Bits::default();
    b.put(16, 0x0AFF);
    b.put(1, 0); // not small
    let size = |b: &mut Bits, v: u32| {
        let v = u64::from(v - 1);
        let (sel, bits) = if v < 1 << 9 { (0, 9) } else if v < 1 << 13 { (1, 13) } else if v < 1 << 18 { (2, 18) } else { (3, 30) };
        b.put(2, sel);
        b.put(bits, v);
    };
    size(&mut b, height);
    b.put(3, 0); // no ratio: width follows
    size(&mut b, width);
    b.put(1, 0); // metadata not all_default
    b.put(1, u64::from(animated)); // extra_fields
    if animated {
        b.put(3, 0); // orientation 1
        b.put(1, 0); // no intrinsic size
        b.put(1, 0); // no preview
        b.put(1, 1); // animation:
        b.put(2, 1); // tps_numerator 1000
        b.put(2, 0); // tps_denominator 1
        b.put(2, 0); // num_loops 0 = forever
        b.put(1, 0); // no timecodes
    }
    b.put(1, 0); // integer samples
    b.put(2, 0); // 8 bits
    b.put(1, 1); // 16-bit buffers suffice
    if alpha {
        b.put(2, 1); // one extra channel
        b.put(1, 1); // default: 8-bit alpha
    } else {
        b.put(2, 0);
    }
    b.put(1, 0); // not XYB
    b.put(1, 1); // sRGB
    if animated {
        b.put(1, 1); // tone mapping all_default
    }
    b.put(2, 0); // no extensions
    b.put(1, 1); // default transform data
    b.pad();
    b.out
}

/// zune-jpegxl's frame header (one modular pass, kReplace) and its TOC.
/// `duration` (ticks) only in an animated image; a frame that is not the
/// last one is not kept as a reference.
fn jxl_frame_header(alpha: bool, duration: Option<u32>, is_last: bool, toc: &[u64]) -> Vec<u8> {
    let mut b = Bits::default();
    b.put(1, 0); // not all_default
    b.put(2, 0); // regular frame
    b.put(1, 1); // modular
    b.put(2, 0); // no flags
    b.put(1, 0); // not YCbCr
    b.put(2, 0); // no upsampling
    if alpha {
        b.put(2, 0);
    }
    b.put(2, 1); // group size 256
    b.put(2, 0); // one pass
    b.put(1, 0); // no crop
    b.put(2, 0); // kReplace
    if alpha {
        b.put(2, 0);
    }
    if let Some(d) = duration {
        match d {
            0 => b.put(2, 0),
            1 => b.put(2, 1),
            2..=255 => { b.put(2, 2); b.put(8, u64::from(d)); }
            _ => { b.put(2, 3); b.put(32, u64::from(d)); }
        }
    }
    b.put(1, u64::from(is_last));
    if !is_last {
        b.put(2, 0); // save_as_reference 0
    }
    b.put(2, 0); // no name
    b.put(1, 0); // restoration filter not all_default
    b.put(1, 0); // no gaborish
    b.put(2, 0); // no EPF
    b.put(2, 0); // no LF extensions
    b.put(2, 0); // no FH extensions
    b.put(1, 0); // no TOC permutation
    b.pad();
    for &size in toc {
        if size < 1 << 10 {
            b.put(2, 0); b.put(10, size);
        } else if size - 1024 < 1 << 14 {
            b.put(2, 1); b.put(14, size - 1024);
        } else if size - 17408 < 1 << 22 {
            b.put(2, 2); b.put(22, size - 17408);
        } else {
            b.put(2, 3); b.put(30, size - 4211712);
        }
    }
    b.pad();
    b.out
}

/// H26: an animated image as a lossless animated JPEG XL, no metadata.
/// `frames`: RGBA bytes each (as `encode_jxl_lossless`, changed in place),
/// `delays_ms` one per frame. zune-jpegxl writes single frames only: each is
/// encoded alone and its frame data is re-framed under an animated header.
/// The headers zune wrote are compared bit for bit with ours first, so a
/// zune update that changes them is an error, not a broken file.
pub fn encode_jxl_animated(frames: &mut [Vec<u8>], width: u32, height: u32, delays_ms: &[u32], has_alpha: bool, out: &Path) -> Result<(), String> {
    let pixels = width as u64 * height as u64;
    if frames.is_empty() || frames.len() > MAX_ANIMATION_FRAMES || frames.len() != delays_ms.len()
        || pixels * frames.len() as u64 > MAX_IMAGE_PIXELS
    {
        return Err("Too many frames or too large".to_string());
    }
    let plain_image = jxl_image_header(width, height, has_alpha, false);
    let plain_frame = jxl_frame_header(has_alpha, None, true, &[]);
    let (gx, gy) = ((width as u64).div_ceil(256), (height as u64).div_ceil(256));
    let toc_len = (if gx * gy == 1 { 1 } else { 2 + (width as u64).div_ceil(2048) * (height as u64).div_ceil(2048) + gx * gy }) as usize;
    let mut encoded = jxl_image_header(width, height, has_alpha, true);
    let count = frames.len();
    for (i, frame) in frames.iter_mut().enumerate() {
        let single = jxl_codestream(frame, width, height, has_alpha)?;
        let toc_at = plain_image.len() + plain_frame.len();
        if !single.starts_with(&plain_image) || single.get(plain_image.len()..toc_at) != Some(&plain_frame[..]) {
            return Err("JPEG XL: unexpected encoder header".to_string());
        }
        // Read the TOC back (same codes as `jxl_frame_header` writes).
        let (mut pos, mut toc) = (toc_at * 8, Vec::with_capacity(toc_len));
        let mut read = |n: usize| -> Option<u64> {
            let mut v = 0u64;
            for k in 0..n {
                let bit = (single.get((pos + k) / 8)? >> ((pos + k) % 8)) & 1;
                v |= u64::from(bit) << k;
            }
            pos += n;
            Some(v)
        };
        for _ in 0..toc_len {
            let size = match read(2) {
                Some(0) => read(10),
                Some(1) => read(14).map(|v| v + 1024),
                Some(2) => read(22).map(|v| v + 17408),
                Some(_) => read(30).map(|v| v + 4211712),
                None => None,
            };
            toc.push(size.ok_or("JPEG XL: short frame")?);
        }
        let data = &single[pos.div_ceil(8)..];
        if toc.iter().sum::<u64>() != data.len() as u64 {
            return Err("JPEG XL: unexpected encoder output".to_string());
        }
        let is_last = i + 1 == count;
        // Duration 0 would make the frame a hidden layer of the next one.
        encoded.extend(jxl_frame_header(has_alpha, Some(delays_ms[i].max(1)), is_last, &toc));
        encoded.extend_from_slice(data);
    }
    std::fs::write(out, encoded).map_err(|e| e.to_string())
}

/// Whether a JPEG XL file says it is animated, from its headers only (the
/// first 64 KiB; a longer ICC profile reads as "not animated").
pub fn jxl_is_animated(src: &Path) -> bool {
    use jxl_oxide::{InitializeResult, JxlImage};
    let mut head = Vec::new();
    if File::open(src).and_then(|f| f.take(64 << 10).read_to_end(&mut head)).is_err() {
        return false;
    }
    let mut image = JxlImage::builder().build_uninit();
    if image.feed_bytes(&head).is_err() {
        return false;
    }
    matches!(image.try_init(), Ok(InitializeResult::Initialized(i)) if i.image_header().metadata.animation.is_some())
}

/// GIF LZW image data of palette indices (8-bit minimum code size), as
/// sub-blocks. Code width and table reset follow gifenc.
fn gif_lzw(indices: &[u8], out: &mut Vec<u8>) {
    const CLEAR: u64 = 256;
    out.push(8);
    let mut dict: std::collections::HashMap<(u16, u8), u16> = std::collections::HashMap::new();
    let (mut next, mut size) = (258u16, 9u32);
    let mut b = Bits::default();
    b.put(size, CLEAR);
    let mut cur: Option<u16> = None;
    for &px in indices {
        let Some(c) = cur else {
            cur = Some(u16::from(px));
            continue;
        };
        if let Some(&code) = dict.get(&(c, px)) {
            cur = Some(code);
            continue;
        }
        b.put(size, u64::from(c));
        if next < 4096 {
            if u32::from(next) == 1 << size {
                size += 1;
            }
            dict.insert((c, px), next);
            next += 1;
        } else {
            b.put(size, CLEAR);
            dict.clear();
            (next, size) = (258, 9);
        }
        cur = Some(u16::from(px));
    }
    if let Some(c) = cur {
        b.put(size, u64::from(c));
    }
    b.put(size, 257); // end of information
    b.pad();
    for block in b.out.chunks(255) {
        out.push(block.len() as u8);
        out.extend_from_slice(block);
    }
    out.push(0);
}

/// H26: a received animated JPEG XL as an animated GIF for the viewers
/// (neither Android nor GTK plays JPEG XL). One fixed 6x7x6 colour cube for
/// all frames, alpha below half is transparent. ponytail: no dithering, banding
/// on gradients; a per-frame median-cut palette if that shows.
pub fn jxl_to_gif(src: &Path, out: &Path) -> Result<(), String> {
    use jxl_oxide::{AllocTracker, EnumColourEncoding, JxlImage, RenderingIntent};
    let mut image = JxlImage::builder()
        .alloc_tracker(AllocTracker::with_limit(512 << 20))
        .open(src)
        .map_err(|e| format!("JPEG XL: {e}"))?;
    image.request_color_encoding(EnumColourEncoding::srgb(RenderingIntent::Relative));
    let (width, height) = (image.width(), image.height());
    let frames = image.num_loaded_keyframes();
    if width > u16::MAX as u32 || height > u16::MAX as u32 || frames > MAX_ANIMATION_FRAMES
        || width as u64 * height as u64 * frames as u64 > MAX_IMAGE_PIXELS
    {
        return Err("Image too large".to_string());
    }
    if frames == 0 {
        return Err("JPEG XL: no frame".to_string());
    }
    // Ticks to centiseconds; a still image gets no delay.
    let (tps_num, tps_den) = image.image_header().metadata.animation.as_ref()
        .map_or((1, 0), |a| (u64::from(a.tps_numerator).max(1), u64::from(a.tps_denominator)));
    const TRANSPARENT: u8 = 255;
    let mut gif = b"GIF89a".to_vec();
    gif.extend_from_slice(&(width as u16).to_le_bytes());
    gif.extend_from_slice(&(height as u16).to_le_bytes());
    gif.extend_from_slice(&[0xF7, 0, 0]); // global table of 256 colours
    for i in 0..256u32 {
        let rgb = if i < 252 { [i / 42 * 51, i / 6 % 7 * 255 / 6, i % 6 * 51] } else { [0; 3] };
        gif.extend(rgb.map(|c| c as u8));
    }
    gif.extend_from_slice(b"\x21\xFF\x0BNETSCAPE2.0\x03\x01\0\0\0"); // loop forever
    let mut row = Vec::new();
    let mut indices = Vec::with_capacity(width as usize * height as usize);
    for k in 0..frames {
        let render = image.render_frame(k).map_err(|e| format!("JPEG XL: {e}"))?;
        let mut stream = render.stream();
        let ch = stream.channels() as usize;
        if !(1..=4).contains(&ch) || (stream.width(), stream.height()) != (width, height) {
            return Err("JPEG XL: unexpected frame layout".to_string());
        }
        let has_alpha = ch == 2 || ch == 4;
        row.resize(width as usize * ch, 0);
        indices.clear();
        for _ in 0..height {
            let mut filled = 0;
            while filled < row.len() {
                let n = stream.write_to_buffer(&mut row[filled..]);
                if n == 0 {
                    return Err("JPEG XL: frame ended early".to_string());
                }
                filled += n;
            }
            for p in row.chunks(ch) {
                let (r, g, b) = if ch >= 3 { (p[0], p[1], p[2]) } else { (p[0], p[0], p[0]) };
                indices.push(if has_alpha && p[ch - 1] < 128 {
                    TRANSPARENT
                } else {
                    let q = |v: u8, levels: u32| (u32::from(v) * (levels - 1) + 127) / 255;
                    (q(r, 6) * 42 + q(g, 7) * 6 + q(b, 6)) as u8
                });
            }
        }
        let delay = (u64::from(render.duration()) * tps_den * 100 / tps_num).min(u16::MAX as u64) as u16;
        // Disposal 2 (clear) under transparency, else 1 (keep).
        let packed = if has_alpha { 2 << 2 | 1 } else { 1 << 2 };
        gif.extend_from_slice(&[0x21, 0xF9, 4, packed]);
        gif.extend_from_slice(&delay.to_le_bytes());
        gif.extend_from_slice(&[TRANSPARENT, 0, 0x2C, 0, 0, 0, 0]);
        gif.extend_from_slice(&(width as u16).to_le_bytes());
        gif.extend_from_slice(&(height as u16).to_le_bytes());
        gif.push(0);
        gif_lzw(&indices, &mut gif);
    }
    gif.push(0x3B);
    std::fs::write(out, gif).map_err(|e| e.to_string())
}

/// A received JPEG XL as PNG: no Android version decodes JPEG XL, and the
/// Linux viewer takes the common formats only. The file is the sender's: its
/// size is checked before the frame is rendered, and the decoder's
/// allocations are capped.
pub fn jxl_to_png(src: &Path, out: &Path) -> Result<(), String> {
    use jxl_oxide::{AllocTracker, EnumColourEncoding, JxlImage, PixelFormat, RenderingIntent};
    let mut image = JxlImage::builder()
        .alloc_tracker(AllocTracker::with_limit(512 << 20))
        .open(src)
        .map_err(|e| format!("JPEG XL: {e}"))?;
    // The PNG carries no colour profile: render in sRGB.
    image.request_color_encoding(EnumColourEncoding::srgb(RenderingIntent::Relative));
    if image.width() as u64 * image.height() as u64 > MAX_IMAGE_PIXELS {
        return Err("Image too large".to_string());
    }
    let color = match image.pixel_format() {
        PixelFormat::Gray => png::ColorType::Grayscale,
        PixelFormat::Graya => png::ColorType::GrayscaleAlpha,
        PixelFormat::Rgb => png::ColorType::Rgb,
        PixelFormat::Rgba => png::ColorType::Rgba,
        _ => return Err("Unsupported JPEG XL colour format".to_string()),
    };
    if image.num_loaded_keyframes() == 0 {
        return Err("JPEG XL: no frame".to_string());
    }
    let render = image.render_frame(0).map_err(|e| format!("JPEG XL: {e}"))?;
    let mut stream = render.stream();
    let (width, height) = (stream.width(), stream.height());
    if stream.channels() as usize != color.samples() {
        return Err("JPEG XL: unexpected channel count".to_string());
    }
    let mut encoder = png::Encoder::new(std::io::BufWriter::new(File::create(out).map_err(|e| e.to_string())?), width, height);
    encoder.set_color(color);
    encoder.set_depth(png::BitDepth::Eight);
    let mut writer = encoder.write_header().map_err(|e| e.to_string())?;
    // Row by row: no second full-size buffer next to the rendered frame.
    let mut rows = writer.stream_writer().map_err(|e| e.to_string())?;
    let mut row = vec![0u8; width as usize * color.samples()];
    for _ in 0..height {
        let mut filled = 0;
        while filled < row.len() {
            let n = stream.write_to_buffer(&mut row[filled..]);
            if n == 0 {
                return Err("JPEG XL: frame ended early".to_string());
            }
            filled += n;
        }
        rows.write_all(&row).map_err(|e| e.to_string())?;
    }
    rows.finish().map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jpeg_trailer_and_png_text_are_dropped() {
        let path = std::env::temp_dir().join(format!("typeon-meta-{}", std::process::id()));
        // SOI, APP0, SOS, entropy data with a stuffed byte and a restart
        // marker, a DHT between scans, a second SOS, EOI, then a trailer.
        let mut jpeg = vec![0xFF, 0xD8, 0xFF, 0xE0, 0, 4, 1, 2, 0xFF, 0xDA, 0, 3, 9, 0x11, 0xFF, 0x00, 0x22, 0xFF, 0xD3, 0x33];
        jpeg.extend_from_slice(&[0xFF, 0xC4, 0, 3, 7, 0xFF, 0xDA, 0, 3, 9, 0x44, 0xFF, 0xD9]);
        let eoi = jpeg.len() as u64;
        jpeg.extend_from_slice(b"MOTIONPHOTO");
        std::fs::write(&path, &jpeg).unwrap();
        let (ranges, _) = jpeg_metadata_ranges(&mut File::open(&path).unwrap()).unwrap();
        assert_eq!(ranges, vec![(eoi, jpeg.len() as u64)]);

        let chunk = |kind: &[u8; 4], body: &[u8]| {
            let mut c = (body.len() as u32).to_be_bytes().to_vec();
            c.extend_from_slice(kind);
            c.extend_from_slice(body);
            c.extend_from_slice(&[0; 4]);
            c
        };
        let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
        png.extend(chunk(b"IHDR", &[0; 13]));
        let text_at = png.len() as u64;
        png.extend(chunk(b"tEXt", b"GPS"));
        let text_end = png.len() as u64;
        png.extend(chunk(b"IDAT", &[1, 2]));
        png.extend(chunk(b"IEND", &[]));
        std::fs::write(&path, &png).unwrap();
        assert_eq!(png_metadata_ranges(&mut File::open(&path).unwrap()), Some(vec![(text_at, text_end)]));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn plain_chunks_read_back_give_the_file_hash() {
        let base = std::env::temp_dir().join(format!("typeon-att-{}", std::process::id()));
        let (src, enc) = (base.with_extension("src"), base.with_extension("enc"));
        std::fs::write(&src, vec![7u8; 40]).unwrap();
        let key = [1u8; 32];
        let (total, sha) = encrypt_file_to_disk_with(&src, &enc, &key, 16).unwrap();
        let mut hasher = Sha256::new();
        for i in 0..total_chunks_with(total, 16) {
            hasher.update(read_plain_chunk_with(&enc, i, &key, 16).unwrap());
        }
        assert_eq!(hex::encode(hasher.finalize()), sha);
        assert!(read_plain_chunk_with(&enc, 0, &[2u8; 32], 16).is_err());
        let _ = std::fs::remove_file(&src);
        let _ = std::fs::remove_file(&enc);
    }

    #[test]
    fn hi_res_jpeg_xl_opens_as_the_same_pixels() {
        let base = std::env::temp_dir().join(format!("typeon-jxl-{}", std::process::id()));
        let (jxl, out) = (base.with_extension("jxl"), base.with_extension("png"));
        let (w, h) = (7u32, 5u32);
        let rgba: Vec<u8> = (0..w * h * 4).map(|i| (i * 37 % 251) as u8).collect();
        for has_alpha in [true, false] {
            encode_jxl_lossless(&mut rgba.clone(), w, h, has_alpha, &jxl).unwrap();
            jxl_to_png(&jxl, &out).unwrap();
            let mut reader = png::Decoder::new(std::io::BufReader::new(File::open(&out).unwrap())).read_info().unwrap();
            let mut got = vec![0u8; reader.output_buffer_size().unwrap()];
            reader.next_frame(&mut got).unwrap();
            let want: Vec<u8> = if has_alpha {
                rgba.clone()
            } else {
                rgba.chunks(4).flat_map(|p| p[..3].to_vec()).collect()
            };
            assert_eq!(got, want, "alpha={has_alpha}");
        }
        assert!(encode_jxl_lossless(&mut vec![0; 4], 1, 1, true, &jxl).is_err(), "1x1");
        assert!(encode_jxl_lossless(&mut vec![0; 8], 2, 2, true, &jxl).is_err(), "short buffer");
        let _ = std::fs::remove_file(&jxl);
        let _ = std::fs::remove_file(&out);
    }

    #[test]
    fn animated_jpeg_xl_keeps_every_frame_and_delay() {
        use jxl_oxide::JxlImage;
        let base = std::env::temp_dir().join(format!("typeon-anim-{}", std::process::id()));
        let (jxl, gif) = (base.with_extension("jxl"), base.with_extension("gif"));
        // 300 wide: two groups, so the multi-entry TOC path runs too; 600x400
        // runs the GIF LZW table resets.
        for (w, h, has_alpha) in [(7u32, 5u32, true), (300, 3, false), (600, 400, true)] {
            let frames: Vec<Vec<u8>> = (0..3u32).map(|f| (0..w * h * 4).map(|i| ((i + f * 11) * 37 % 251) as u8).collect()).collect();
            encode_jxl_animated(&mut frames.clone(), w, h, &[40, 300, 1000], has_alpha, &jxl).unwrap();
            let image = JxlImage::builder().open(&jxl).unwrap();
            assert_eq!(image.num_loaded_keyframes(), 3);
            for (k, want_ms) in [40u32, 300, 1000].into_iter().enumerate() {
                let render = image.render_frame(k).unwrap();
                assert_eq!(render.duration(), want_ms);
                let mut stream = render.stream();
                let mut got = vec![0u8; (w * h) as usize * stream.channels() as usize];
                stream.write_to_buffer(&mut got);
                let want: Vec<u8> = if has_alpha { frames[k].clone() } else { frames[k].chunks(4).flat_map(|p| p[..3].to_vec()).collect() };
                assert_eq!(got, want, "frame {k} {w}x{h}");
            }
            jxl_to_gif(&jxl, &gif).unwrap();
            let out = std::fs::read(&gif).unwrap();
            assert!(out.starts_with(b"GIF89a") && out.ends_with(&[0x3B]));
        }
        assert!(encode_jxl_animated(&mut [vec![0; 16]], 2, 2, &[], true, &jxl).is_err(), "delay count");
        let _ = std::fs::remove_file(&jxl);
        let _ = std::fs::remove_file(&gif);
    }

    #[test]
    fn exif_is_cut_from_a_jpeg_and_a_doubtful_jpeg_is_refused() {
        let base = std::env::temp_dir().join(format!("typeon-jpg-{}", std::process::id()));
        let (src, enc) = (base.with_extension("src"), base.with_extension("enc"));
        let key = [1u8; 32];
        let sent = |bytes: &[u8]| -> Vec<u8> {
            std::fs::write(&src, bytes).unwrap();
            let (total, _) = encrypt_file_to_disk_with(&src, &enc, &key, 16).unwrap();
            let out: Vec<u8> = (0..total_chunks_with(total, 16)).flat_map(|i| read_plain_chunk_with(&enc, i, &key, 16).unwrap()).collect();
            assert_eq!(out.len() as u64, total);
            out
        };
        let soi = [0xFF, 0xD8];
        let jfif = [0xFF, 0xE0, 0, 4, b'J', b'F'];
        let exif = [0xFF, 0xE1, 0, 6, b'E', b'x', b'i', b'f'];
        let icc = [0xFF, 0xE2, 0, 4, b'I', b'C'];
        let iptc = [0xFF, 0xED, 0, 4, b'P', b'S'];
        // Image data may hold anything, a marker of a metadata segment too.
        let scan = [0xFF, 0xDA, 0, 2, 1, 2, 0xFF, 0xE1, 0, 2, 0xFF, 0xD9];
        let photo = [&soi[..], &jfif, &exif, &icc, &iptc, &scan].concat();
        assert_eq!(sent(&photo), [&soi[..], &jfif, &icc, &scan].concat());
        // A rotated photo keeps its orientation, and only that.
        let rotated = b"\xFF\xE1\0\x32Exif\0\0II*\0\x08\0\0\0\x02\0\x0F\x01\x02\0\x01\0\0\0A\0\0\0\x12\x01\x03\0\x01\0\0\0\x06\0\0\0\0\0\0\0GPS!";
        assert_eq!(rotated.len(), 2 + 0x32);
        let photo = [&soi[..], &jfif, &rotated[..], &exif, &scan].concat();
        assert_eq!(sent(&photo), [&soi[..], &orientation_segment(6), &jfif, &scan].concat());
        assert_eq!(exif_orientation(&orientation_segment(6)[4..]), Some(6));
        // A segment longer than the file, or no start-of-scan: refused.
        for doubtful in [[&soi[..], &exif, &[0xFF, 0xE1, 0xFF, 0xFF, 1]].concat(), [&soi[..], &exif].concat()] {
            std::fs::write(&src, &doubtful).unwrap();
            assert!(encrypt_file_to_disk_with(&src, &enc, &key, 16).is_err());
        }
        // Not a JPEG: unchanged.
        let other = [&[0x89, b'P', b'N', b'G'][..], &exif].concat();
        assert_eq!(sent(&other), other);
        let _ = std::fs::remove_file(&src);
        let _ = std::fs::remove_file(&enc);
    }
}
