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
//! karşılaştırması (bkz. `decrypt_file_from_disk`).
//!
//! Diskte saklanan `.enc` dosyası, parçaların OLDUĞU GİBİ (şifreli, ağdan
//! geldiği/gideceği biçimde) art arda eklenmesinden oluşur — bu, bir
//! cihazın indirdiği bir dosyayı BAŞKA bir isteyene tekrar şifrelemeden
//! servis edebilmesini sağlar (bkz. `read_chunk_from_disk`).

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
    Chunk { data: Vec<u8> },
    /// `file_id` bilinmiyor (hiç sunulmuyor/tamamlanmamış) veya
    /// `chunk_index` aralık dışı.
    NotFound,
}

/// `total_size` baytlık bir dosyanın kaç `FILE_CHUNK_SIZE`'lık parçaya
/// böleceğini hesaplar (0 baytlık dosya için 0 döner — özel durum
/// gerektirmez, çağıran tarafın "0 parça = hemen tamamlandı" mantığı
/// doğal olarak çalışır).
pub fn total_chunks(total_size: u64) -> u32 {
    ((total_size + FILE_CHUNK_SIZE as u64 - 1) / FILE_CHUNK_SIZE as u64) as u32
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

/// `source_path`'i (kullanıcının seçtiği dosya — Kotlin tarafından zaten
/// yerel bir yola kopyalanmış olmalı, content:// URI burada işlenmez)
/// `FILE_CHUNK_SIZE`'lık parçalar hâlinde OKUYUP her parçayı ayrı ayrı
/// şifreleyerek `dest_enc_path`'e yazar — dosyanın TAMAMI hiçbir anda
/// bellekte olmaz (4GB'a kadar bir dosya için bu şart). Dönüş: (toplam
/// bayt, plaintext SHA-256 hex).
pub fn encrypt_file_to_disk(source_path: &Path, dest_enc_path: &Path, file_key: &[u8; 32]) -> Result<(u64, String), String> {
    let cipher = ChaCha20Poly1305::new_from_slice(file_key).map_err(|_| "Invalid file key")?;
    let mut src = File::open(source_path).map_err(|e| e.to_string())?;
    let mut dest = File::create(dest_enc_path).map_err(|e| e.to_string())?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; FILE_CHUNK_SIZE];
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
        if n < FILE_CHUNK_SIZE {
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
pub fn decrypt_file_from_disk(src_enc_path: &Path, dest_plain_path: &Path, file_key: &[u8; 32], expected_sha256_hex: &str) -> Result<(), String> {
    let cipher = ChaCha20Poly1305::new_from_slice(file_key).map_err(|_| "Invalid file key")?;
    let mut src = File::open(src_enc_path).map_err(|e| e.to_string())?;
    let mut dest = File::create(dest_plain_path).map_err(|e| e.to_string())?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; FILE_CHUNK_SIZE + 16];
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
pub fn read_chunk_from_disk(enc_path: &Path, chunk_index: u32) -> Result<Option<Vec<u8>>, String> {
    let mut f = match File::open(enc_path) {
        Ok(f) => f,
        Err(_) => return Ok(None),
    };
    let offset = chunk_index as u64 * (FILE_CHUNK_SIZE as u64 + 16);
    if f.seek(SeekFrom::Start(offset)).is_err() {
        return Ok(None);
    }
    let mut buf = vec![0u8; FILE_CHUNK_SIZE + 16];
    let n = read_full(&mut f, &mut buf).map_err(|e| e.to_string())?;
    if n == 0 {
        return Ok(None);
    }
    buf.truncate(n);
    Ok(Some(buf))
}

/// Bir gelen parçayı doğrulayıp (AEAD etiketi kontrolü) `.enc` dosyasına
/// EKLER (append) — indirme her zaman sıralı (0, 1, 2, ...) yapıldığından
/// (bkz. lib.rs `DownloadState`/`request_next_chunk`) sıralı yazma
/// yeterlidir, seek gerekmez. Diske yazılan hâlâ ŞİFRELİ bayt dizisi
/// (plaintext atılır, sadece geçerliliği kanıtlamak için çözülür) — bkz.
/// modül başı notu.
pub fn append_verified_chunk(dest_enc_path: &Path, chunk_index: u32, ciphertext: &[u8], file_key: &[u8; 32]) -> Result<usize, String> {
    let cipher = ChaCha20Poly1305::new_from_slice(file_key).map_err(|_| "Invalid file key")?;
    let nonce = nonce_from_chunk_index(chunk_index);
    let plaintext = cipher.decrypt(&nonce, ciphertext).map_err(|_| format!("Chunk {} authentication failed", chunk_index))?;
    let plaintext_len = plaintext.len();
    let mut f = OpenOptions::new().create(true).append(true).open(dest_enc_path).map_err(|e| e.to_string())?;
    f.write_all(ciphertext).map_err(|e| e.to_string())?;
    Ok(plaintext_len)
}
