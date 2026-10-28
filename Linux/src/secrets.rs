//! The local secret vault: this device's long-term secret key bundle plus the
//! two 32-byte symmetric keys the core wants handed back on every launch
//! (message-archive key, skipped-message-key cache key).
//!
//! On Android these live in files encrypted by a hardware-backed Keystore key
//! (`KeystoreCrypto`/`IdentityManager`/`MessageHistoryManager`/
//! `SkippedKeyManager`). The desktop equivalent is the session's own secret
//! store — KDE Wallet or GNOME Keyring — which is encrypted at rest and
//! unlocked by the user's login credentials. See [`crate::keyring`]; without
//! one the app refuses to start, so there is no unencrypted path through this
//! module.
//!
//! The file is sealed with ChaCha20-Poly1305. The key is:
//!
//!     SHA-256("typeon-vault-v2" ‖ wallet_key ‖ argon2id(passphrase, salt)?)
//!
//! The wallet key is 32 random bytes that exist only inside the wallet. An
//! optional passphrase is folded in as a *second* factor, not an alternative
//! to the first: with one set, an attacker needs both the unlocked wallet and
//! something the user knows. Both halves are required to open the vault, so
//! forgetting the passphrase loses the device — that is what re-linking from
//! the phone is for.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::keyring;

/// V2 = wallet-sealed. There is no V1 in the wild: the file-only format never
/// shipped, so there is nothing to migrate and no weaker format to fall back
/// to if this one fails to open.
const MAGIC: &[u8; 8] = b"TYPEONV2";
/// Domain separator, so the vault key can never coincide with anything else
/// derived from the same wallet secret.
const KDF_DOMAIN: &[u8] = b"typeon-vault-v2";

const MODE_WALLET: u8 = 0;
const MODE_WALLET_PASSPHRASE: u8 = 1;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const HEADER_LEN: usize = MAGIC.len() + 1 + SALT_LEN + NONCE_LEN;

/// 64 MiB / 3 passes / 1 lane. Comfortably past the point where offline
/// guessing is cheap, still well under a second on a desktop.
const ARGON_MEMORY_KIB: u32 = 64 * 1024;
const ARGON_PASSES: u32 = 3;
const ARGON_LANES: u32 = 1;

pub struct Vault {
    /// CBOR secret key bundle as produced by the core's `create_identity` —
    /// opaque here, handed straight back via `load_secret_bundle`.
    pub identity_bundle: Vec<u8>,
    pub history_key: [u8; 32],
    pub skipped_key: [u8; 32],
}

impl Drop for Vault {
    fn drop(&mut self) {
        self.identity_bundle.zeroize();
        self.history_key.zeroize();
        self.skipped_key.zeroize();
    }
}

impl Vault {
    /// A fresh vault for a brand-new identity: the caller supplies the bundle
    /// the core just generated, the two cache keys are random.
    pub fn new(identity_bundle: Vec<u8>) -> Self {
        let mut history_key = [0u8; 32];
        let mut skipped_key = [0u8; 32];
        OsRng.fill_bytes(&mut history_key);
        OsRng.fill_bytes(&mut skipped_key);
        Self {
            identity_bundle,
            history_key,
            skipped_key,
        }
    }

    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.identity_bundle.len() + 64);
        out.extend_from_slice(&(self.identity_bundle.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.identity_bundle);
        out.extend_from_slice(&self.history_key);
        out.extend_from_slice(&self.skipped_key);
        out
    }

    fn decode(raw: &[u8]) -> Result<Self, String> {
        if raw.len() < 4 {
            return Err("vault body truncated".into());
        }
        let bundle_len = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]) as usize;
        let key_start = 4 + bundle_len;
        if raw.len() < key_start + 64 {
            return Err("vault body truncated".into());
        }
        let mut history_key = [0u8; 32];
        let mut skipped_key = [0u8; 32];
        history_key.copy_from_slice(&raw[key_start..key_start + 32]);
        skipped_key.copy_from_slice(&raw[key_start + 32..key_start + 64]);
        Ok(Self {
            identity_bundle: raw[4..key_start].to_vec(),
            history_key,
            skipped_key,
        })
    }
}

pub fn vault_path(dir: &Path) -> PathBuf {
    dir.join("vault.bin")
}

pub fn exists(dir: &Path) -> bool {
    vault_path(dir).exists()
}

/// Whether the stored vault also needs a passphrase — read from its header
/// alone, so the launch flow knows whether to prompt before holding anything
/// secret.
pub fn is_passphrase_protected(dir: &Path) -> bool {
    // M155: only the magic + mode byte, not the whole vault.
    use std::io::Read;
    let mut head = vec![0u8; MAGIC.len() + 1];
    match std::fs::File::open(vault_path(dir)).and_then(|mut f| f.read_exact(&mut head)) {
        Ok(()) => head[MAGIC.len()] == MODE_WALLET_PASSPHRASE,
        Err(_) => false,
    }
}

/// Seals the vault. Creates the wallet key on first use; reuses it afterwards
/// so the entry does not churn every time settings change.
///
/// `passphrase` empty means "wallet only".
pub fn save(dir: &Path, vault: &Vault, passphrase: &str) -> Result<(), String> {
    let profile = dir.to_string_lossy().to_string();
    let wallet_key = match keyring::load_key(&profile)? {
        Some(key) => Zeroizing::new(key),
        None => {
            let mut fresh = Zeroizing::new([0u8; 32]);
            OsRng.fill_bytes(&mut *fresh);
            keyring::store_key(&profile, &fresh)?;
            fresh
        }
    };

    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce_bytes);

    let mode = if passphrase.is_empty() {
        MODE_WALLET
    } else {
        MODE_WALLET_PASSPHRASE
    };

    let sealed = {
        let mut key = derive_key(&wallet_key, passphrase, &salt)?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let mut body = vault.encode();
        let result = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), body.as_ref())
            .map_err(|_| "vault encryption failed".to_string());
        body.zeroize();
        key.zeroize();
        result?
    };

    let mut out = Vec::with_capacity(HEADER_LEN + sealed.len());
    out.extend_from_slice(MAGIC);
    out.push(mode);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&sealed);

    write_private(&vault_path(dir), &out)?;
    remember_archive_seal(vault);
    Ok(())
}

pub fn load(dir: &Path, passphrase: &str) -> Result<Vault, String> {
    let raw = std::fs::read(vault_path(dir)).map_err(|e| e.to_string())?;
    if raw.len() < HEADER_LEN || &raw[..MAGIC.len()] != MAGIC {
        return Err("not a Typeon vault file".into());
    }
    let mode = raw[MAGIC.len()];
    if mode != MODE_WALLET && mode != MODE_WALLET_PASSPHRASE {
        return Err("unsupported vault format".into());
    }
    let salt = &raw[MAGIC.len() + 1..MAGIC.len() + 1 + SALT_LEN];
    let nonce_bytes = &raw[MAGIC.len() + 1 + SALT_LEN..HEADER_LEN];
    let payload = &raw[HEADER_LEN..];

    let profile = dir.to_string_lossy().to_string();
    let wallet_key = keyring::load_key(&profile)?.map(Zeroizing::new).ok_or_else(|| {
        format!(
            "{} no longer holds this device's vault key. Without it the vault cannot be opened \
             — link this computer to your account again.",
            keyring_name()
        )
    })?;

    let mut body = {
        let mut key = derive_key(&wallet_key, passphrase, salt)?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let result = cipher
            .decrypt(Nonce::from_slice(nonce_bytes), payload)
            // AEAD cannot tell a wrong passphrase from a damaged file, and
            // neither should the message.
            .map_err(|_| {
                if mode == MODE_WALLET_PASSPHRASE {
                    "wrong passphrase, or the vault file is damaged".to_string()
                } else {
                    "the vault file is damaged, or was sealed by a different wallet".to_string()
                }
            });
        key.zeroize();
        result?
    };

    let vault = Vault::decode(&body);
    body.zeroize();
    if let Ok(vault) = &vault {
        remember_archive_seal(vault);
    }
    vault
}

/// Re-seals an already-open vault under a new passphrase (empty = wallet only).
pub fn change_passphrase(dir: &Path, vault: &Vault, new_passphrase: &str) -> Result<(), String> {
    save(dir, vault, new_passphrase)
}

/// Defter #39: burası her zaman `Backend::Unknown` kullanıyordu, yani hata
/// mesajı hiçbir zaman "KDE Wallet"/"GNOME Keyring" diyemiyordu. Artık
/// gerçekten tespit edilen arka uç adlandırılıyor.
fn keyring_name() -> &'static str {
    match keyring::ensure_available() {
        Ok(backend) => backend.display_name(),
        Err(_) => keyring::Backend::Unknown.display_name(),
    }
}

/// Folds the wallet key and the optional passphrase into one AEAD key. The
/// wallet key is always present; the Argon2id block is only mixed in when a
/// passphrase is set, so both factors are needed to open a sealed vault.
fn derive_key(wallet_key: &[u8; 32], passphrase: &str, salt: &[u8]) -> Result<[u8; 32], String> {
    let mut hasher = Sha256::new();
    hasher.update(KDF_DOMAIN);
    hasher.update(wallet_key);

    if !passphrase.is_empty() {
        let params = Params::new(ARGON_MEMORY_KIB, ARGON_PASSES, ARGON_LANES, Some(32))
            .map_err(|e| e.to_string())?;
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut stretched = [0u8; 32];
        argon
            .hash_password_into(passphrase.as_bytes(), salt, &mut stretched)
            .map_err(|e| e.to_string())?;
        hasher.update(stretched);
        stretched.zeroize();
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&hasher.finalize());
    Ok(key)
}

/// Creates/truncates the file with `0600` **before** any secret reaches it —
/// writing first and chmod'ing after would leave a window where the vault is
/// world-readable.
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;

    // Write a temp file and rename it over: truncating in place means a crash
    // or power loss mid-write leaves a half vault and the identity is gone.
    let tmp = path.with_extension("tmp");
    // Unlink (never follows a symlink) then `create_new` (O_EXCL, refuses a
    // symlink planted in the gap): a fixed temp name must not be a way to
    // overwrite some other file.
    match std::fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.to_string()),
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|e| e.to_string())?;
    // The umask can only strip bits, but chmod BEFORE any secret byte anyway.
    file.set_permissions(std::fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
    file.write_all(bytes).map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())?;
    drop(file);
    std::fs::rename(&tmp, path).map_err(|e| e.to_string())?;
    // Persist the rename itself, or a power loss can bring the old file back.
    if let Some(parent) = path.parent() {
        std::fs::File::open(parent)
            .and_then(|d| d.sync_all())
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Archive root key
// ---------------------------------------------------------------------------
//
// Kept in its own small file rather than inside `vault.bin`, for two reasons.
// The vault needs the user's passphrase to rewrite, and it is dropped right
// after boot — but this key can arrive *later*, from a sibling device over the
// encrypted sync channel, at a moment when no passphrase is on hand. The
// wallet key from the secret store is available at any time, so a standalone
// file sealed under it can be written whenever the key turns up. This also
// mirrors the Android side exactly (`ArchiveKeyManager`, a Keystore-wrapped
// `archive_root_key.enc`), which keeps the two clients easy to compare.
//
// Scope, and why it differs from `history_key`: that one is per *device*,
// random, and not in the recovery file — it only encrypts the local SQLite
// archive. This one is per *identity*, because every device of the same
// identity has to be able to read the server-side archive.

const ARCHIVE_FILE: &str = "archive_root_key.bin";
const ARCHIVE_MAGIC: &[u8] = b"TYPEONARK1";

fn archive_path(dir: &Path) -> PathBuf {
    dir.join(ARCHIVE_FILE)
}

/// Key that seals the archive file, derived from a secret inside the vault
/// and held for the session. The wallet key alone must not open the archive
/// key: with a passphrase set, that would bypass the passphrase.
/// M154: deliberately never zeroized — it lives for the process, like the
/// core's own keys; wiping it at exit would buy nothing.
static ARCHIVE_SEAL: std::sync::Mutex<Option<[u8; 32]>> = std::sync::Mutex::new(None);

fn remember_archive_seal(vault: &Vault) {
    let mut hasher = Sha256::new();
    hasher.update(b"typeon-archive-key-v2");
    hasher.update(vault.history_key);
    let mut key = [0u8; 32];
    key.copy_from_slice(&hasher.finalize());
    *ARCHIVE_SEAL.lock().unwrap_or_else(|e| e.into_inner()) = Some(key);
}

fn archive_cipher() -> Result<ChaCha20Poly1305, String> {
    let key = (*ARCHIVE_SEAL.lock().unwrap_or_else(|e| e.into_inner())).ok_or("the vault is not open")?;
    ChaCha20Poly1305::new_from_slice(&key).map_err(|_| "bad archive key".to_string())
}

/// Reads the stored archive root key. `Ok(None)` only when no file exists;
/// a file that cannot be read or opened is an `Err`, never "no key".
pub fn load_archive_key(dir: &Path) -> Result<Option<[u8; 32]>, String> {
    let raw = match std::fs::read(archive_path(dir)) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    if raw.len() < ARCHIVE_MAGIC.len() + NONCE_LEN + 32 || !raw.starts_with(ARCHIVE_MAGIC) {
        return Err("the archive key file is damaged".into());
    }
    let cipher = archive_cipher()?;
    let nonce_start = ARCHIVE_MAGIC.len();
    let body_start = nonce_start + NONCE_LEN;
    let nonce = Nonce::from_slice(&raw[nonce_start..body_start]);
    let plain = cipher
        .decrypt(nonce, &raw[body_start..])
        .map_err(|_| "the archive key file cannot be opened".to_string())?;
    plain
        .try_into()
        .map(Some)
        .map_err(|_| "the archive key file is damaged".to_string())
}

pub fn store_archive_key(dir: &Path, key: &[u8; 32]) -> Result<(), String> {
    let cipher = archive_cipher()?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, key.as_slice()).map_err(|_| "archive key seal failed")?;

    let mut out = Vec::with_capacity(ARCHIVE_MAGIC.len() + NONCE_LEN + ciphertext.len());
    out.extend_from_slice(ARCHIVE_MAGIC);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    write_private(&archive_path(dir), &out)
}

/// Generates the archive root key if there is none yet, and returns the key
/// in force.
///
/// Called only when the user turns on server-side history, never at first
/// launch — a device that invented its own key before hearing from a sibling
/// would upload an archive its other devices could not read.
pub fn ensure_archive_key(dir: &Path) -> Result<[u8; 32], String> {
    // An unreadable key is an error: replacing it would make the server
    // archive unreadable for every other device of this identity.
    if let Some(existing) = load_archive_key(dir)? {
        return Ok(existing);
    }
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    store_archive_key(dir, &key)?;
    Ok(key)
}
