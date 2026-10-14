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
    let cs = if chunk_size == 0 { FILE_CHUNK_SIZE } else { chunk_size } as u64;
    ((total_size.saturating_add(cs - 1)) / cs) as u32
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
/// Empty for a file that is not a JPEG, and on any doubt about its structure:
/// the file is then sent as it is.
fn jpeg_metadata_ranges(file: &mut File) -> (Vec<(u64, u64)>, Option<u8>) {
    let scan = |file: &mut File| -> Option<(Vec<(u64, u64)>, Option<u8>)> {
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
            // Start of scan: the header is over, the rest is image data.
            if marker == 0xDA {
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
    };
    let found = scan(file).unwrap_or_default();
    // The caller reads from the start. A failed rewind: nothing is skipped
    // (an empty list), and the read below fails or starts where it is.
    if file.seek(SeekFrom::Start(0)).is_err() {
        return (Vec::new(), None);
    }
    found
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
    // of the bytes that are sent.
    let (ranges, orientation) = jpeg_metadata_ranges(&mut src);
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
    let chunk_size = if chunk_size == 0 { FILE_CHUNK_SIZE } else { chunk_size };
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
        chunk_index += 1;
        if n < chunk_size {
            break;
        }
    }
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
    let chunk_size = if chunk_size == 0 { FILE_CHUNK_SIZE } else { chunk_size };
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
        chunk_index += 1;
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
    let chunk_size = if chunk_size == 0 { FILE_CHUNK_SIZE } else { chunk_size };
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
    let chunk_size = if chunk_size == 0 { FILE_CHUNK_SIZE } else { chunk_size };
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
    Ok(plaintext_len)
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn exif_is_cut_from_a_jpeg_and_a_doubtful_file_is_sent_whole() {
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
        // A segment longer than the file: unchanged.
        let cut = [&soi[..], &exif, &[0xFF, 0xE1, 0xFF, 0xFF, 1]].concat();
        assert_eq!(sent(&cut), cut);
        // No start-of-scan after the segments: unchanged.
        let headless = [&soi[..], &exif].concat();
        assert_eq!(sent(&headless), headless);
        // Not a JPEG: unchanged.
        let other = [&[0x89, b'P', b'N', b'G'][..], &exif].concat();
        assert_eq!(sent(&other), other);
        let _ = std::fs::remove_file(&src);
        let _ = std::fs::remove_file(&enc);
    }
}
