//! The system secret store on Windows: DPAPI. Same API as `keyring.rs`.
//!
//! The random 32-byte vault key is sealed with `CryptProtectData` (user
//! scope): only this Windows account, logged in with its own password, can
//! open it again. The sealed blob sits next to the vault as `vault-key.dpapi`,
//! so copying the data directory to another machine or account gets an
//! attacker nothing on its own — the same property the Linux wallet gives.

use crate::i18n::t;
use std::path::{Path, PathBuf};

use windows_sys::Win32::Foundation::{LocalFree, HLOCAL};
use windows_sys::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
};
use zeroize::Zeroize;

/// Ties the blob to Typeon: another program running as the same user cannot
/// open it by accident (it can on purpose; DPAPI does not isolate processes).
const ENTROPY: &[u8] = b"typeon vault key v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Dpapi,
    Unknown,
}

impl Backend {
    pub fn display_name(self) -> &'static str {
        match self {
            Backend::Dpapi => "Windows Data Protection",
            Backend::Unknown => t("the system keyring"),
        }
    }
}

pub enum Unavailable {
    Broken(String),
}

impl Unavailable {
    pub fn heading(&self) -> String {
        t("Windows Data Protection is not working").to_string()
    }

    pub fn detail(&self) -> String {
        let Unavailable::Broken(error) = self;
        tf!(
            "Typeon keeps this device's secret keys sealed with Windows Data Protection \
             (DPAPI) and will not run without it.\n\nDetails: {}",
            error
        )
    }
}

/// DPAPI is part of every Windows install.
pub fn detected() -> Option<Backend> {
    Some(Backend::Dpapi)
}

/// Proves DPAPI works with a sealing round trip. Called once before any
/// window is built.
pub fn ensure_available() -> Result<Backend, Unavailable> {
    let probe = [7u8; 32];
    let sealed = protect(&probe).map_err(Unavailable::Broken)?;
    let mut opened = unprotect(&sealed).map_err(Unavailable::Broken)?;
    let ok = opened == probe;
    opened.zeroize();
    if ok { Ok(Backend::Dpapi) } else { Err(Unavailable::Broken("round trip mismatch".into())) }
}

fn key_path(data_dir: &str) -> PathBuf {
    Path::new(data_dir).join("vault-key.dpapi")
}

/// The vault key for this data directory, or `None` on a first run.
pub fn load_key(data_dir: &str) -> Result<Option<[u8; 32]>, String> {
    let sealed = match std::fs::read(key_path(data_dir)) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(tf!("could not read the vault key: {}", error)),
    };
    let mut secret = unprotect(&sealed).map_err(|error| tf!("could not open the vault key: {}", error))?;
    let key: Result<[u8; 32], String> =
        secret.as_slice().try_into().map_err(|_| t("the stored vault key is not 32 bytes").to_string());
    secret.zeroize();
    key.map(Some)
}

pub fn store_key(data_dir: &str, key: &[u8; 32]) -> Result<(), String> {
    let sealed = protect(key).map_err(|error| tf!("could not seal the vault key: {}", error))?;
    crate::secrets::write_private(&key_path(data_dir), &sealed)
}

/// Removes this profile's vault key ("log out").
pub fn delete_key(data_dir: &str) -> Result<(), String> {
    match std::fs::remove_file(key_path(data_dir)) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
            Err(tf!("could not remove the vault key: {}", error))
        }
        _ => Ok(()),
    }
}

fn blob(bytes: &[u8]) -> CRYPT_INTEGER_BLOB {
    CRYPT_INTEGER_BLOB { cbData: bytes.len() as u32, pbData: bytes.as_ptr() as *mut u8 }
}

/// Copies DPAPI's LocalAlloc'd output out, wipes and frees it.
fn take(out: CRYPT_INTEGER_BLOB) -> Vec<u8> {
    // SAFETY: on success DPAPI hands back `cbData` valid bytes at `pbData`,
    // owned by us and released with LocalFree.
    unsafe {
        let slice = std::slice::from_raw_parts_mut(out.pbData, out.cbData as usize);
        let bytes = slice.to_vec();
        slice.zeroize();
        LocalFree(out.pbData as HLOCAL);
        bytes
    }
}

fn protect(data: &[u8]) -> Result<Vec<u8>, String> {
    let (input, entropy) = (blob(data), blob(ENTROPY));
    let mut out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
    // SAFETY: all pointers are valid for the call; DPAPI only reads the inputs.
    let ok = unsafe {
        CryptProtectData(&input, std::ptr::null(), &entropy, std::ptr::null(), std::ptr::null(), CRYPTPROTECT_UI_FORBIDDEN, &mut out)
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(take(out))
}

fn unprotect(data: &[u8]) -> Result<Vec<u8>, String> {
    let (input, entropy) = (blob(data), blob(ENTROPY));
    let mut out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
    // SAFETY: as in `protect`.
    let ok = unsafe {
        CryptUnprotectData(&input, std::ptr::null_mut(), &entropy, std::ptr::null(), std::ptr::null(), CRYPTPROTECT_UI_FORBIDDEN, &mut out)
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(take(out))
}
