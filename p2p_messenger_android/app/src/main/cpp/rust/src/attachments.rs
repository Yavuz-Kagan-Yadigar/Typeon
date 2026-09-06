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
    Chunk { data: Vec<u8> },
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
