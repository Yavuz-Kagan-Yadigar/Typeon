//! The system secret store — KDE Wallet or GNOME Keyring.
//!
//! Typeon refuses to start without one. The vault holding this device's
//! long-term secret keys is sealed with a random 32-byte key that lives *only*
//! in the desktop's own wallet, which is itself encrypted at rest and unlocked
//! by the user's login credentials. Copying `vault.bin` off the disk therefore
//! gets an attacker nothing on its own.
//!
//! Both wallets speak the same freedesktop Secret Service D-Bus API, so one
//! client covers both:
//!   * GNOME Keyring implements `org.freedesktop.secrets` directly.
//!   * KDE Wallet implements it through `ksecretd` (shipped with `kwalletd6`,
//!     registered as `org.kde.secretservicecompat`), which claims
//!     `org.freedesktop.secrets` as a second name once it starts.
//!
//! That last detail matters. On a KDE box `org.freedesktop.secrets` is often
//! *not* D-Bus activatable in its own right, so a client that just connects
//! blind fails even though a perfectly good wallet is installed.
//! [`ensure_available`] activates the backend under its real name first, which
//! is why this module talks to zbus directly rather than going only through
//! the `secret-service` crate.
//!
//! Each operation opens its own connection. `SecretService` hands out
//! collections and items that borrow from it, so keeping one alive in a struct
//! field would spread a lifetime parameter across the whole app for no gain —
//! these calls happen a handful of times at startup, not in a loop.

use crate::i18n::t;
use std::collections::HashMap;
use std::time::Duration;

use secret_service::blocking::SecretService;
use secret_service::EncryptionType;
use zbus::blocking::fdo::DBusProxy;
use zbus::blocking::Connection;
use zbus::names::{BusName, WellKnownName};
use zeroize::Zeroize;

/// D-Bus name every Secret Service provider ends up owning.
const SECRETS_NAME: &str = "org.freedesktop.secrets";

/// Backends we know how to start, most specific first. A GNOME session usually
/// activates `org.freedesktop.secrets` by itself, so the KDE names are the ones
/// that actually need nudging.
const BACKEND_NAMES: &[&str] = &[
    "org.kde.secretservicecompat",
    "org.kde.kwalletd6",
    "org.kde.kwalletd5",
    "org.gnome.keyring",
];

/// Attributes identifying our entry. Searching by attribute is what the Secret
/// Service API is built around, and it keeps working if the user renames the
/// entry in a wallet manager.
const ATTR_APPLICATION: &str = "typeon";
const ATTR_KEY: &str = "vault-key";
const ITEM_LABEL: &str = "Typeon vault key";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    KdeWallet,
    GnomeKeyring,
    Unknown,
}

impl Backend {
    pub fn display_name(self) -> &'static str {
        match self {
            Backend::KdeWallet => "KDE Wallet",
            Backend::GnomeKeyring => "GNOME Keyring",
            Backend::Unknown => t("the system keyring"),
        }
    }
}

/// Why we cannot proceed, split up so the UI can say something more useful
/// than "keyring error".
pub enum Unavailable {
    /// No session bus at all — a very unusual desktop.
    NoSessionBus(String),
    /// Neither wallet is installed.
    NotInstalled,
    /// Installed, but it would not start or never claimed the Secret Service
    /// name — typically a locked or misconfigured wallet.
    NotRunning { installed: Backend, detail: String },
}

impl Unavailable {
    pub fn heading(&self) -> String {
        match self {
            Unavailable::NoSessionBus(_) => t("No D-Bus session").to_string(),
            Unavailable::NotInstalled => t("No system keyring found").to_string(),
            Unavailable::NotRunning { installed, .. } => {
                tf!("{} is not responding", installed.display_name())
            }
        }
    }

    pub fn detail(&self) -> String {
        match self {
            Unavailable::NoSessionBus(error) => tf!(
                "Typeon could not reach the D-Bus session bus, so it has no way to get at a \
                 secret store.\n\nDetails: {}",
                error
            ),
            Unavailable::NotInstalled => tf!(
                "Typeon keeps this device's secret keys sealed with a key held by your desktop's \
                 secret store, and will not run without one. Neither KDE Wallet nor GNOME \
                 Keyring is installed.\n\nInstall one of them, then start Typeon \
                 again:\n\n    sudo zypper install kwalletd6\n    sudo zypper install \
                 gnome-keyring\n\n(Looked for an owner of {}.)",
                SECRETS_NAME
            ),
            Unavailable::NotRunning { installed, detail } => tf!(
                "{} is installed but did not provide the Secret Service interface \
                 ({}).\n\nUnlocking the wallet once is usually enough — open it from \
                 your desktop settings, or log out and back in — then start Typeon \
                 again.\n\nDetails: {}",
                installed.display_name(),
                SECRETS_NAME,
                detail
            ),
        }
    }
}

static DETECTED: std::sync::OnceLock<Backend> = std::sync::OnceLock::new();

/// The backend found by the startup probe, without any D-Bus traffic.
pub fn detected() -> Option<Backend> {
    DETECTED.get().copied()
}

/// Checks for a usable Secret Service, activating whichever wallet is
/// installed, and proves we can actually talk to it. Blocking; called once
/// before any window is built.
pub fn ensure_available() -> Result<Backend, Unavailable> {
    let connection =
        Connection::session().map_err(|error| Unavailable::NoSessionBus(error.to_string()))?;
    let dbus =
        DBusProxy::new(&connection).map_err(|error| Unavailable::NoSessionBus(error.to_string()))?;

    let installed = installed_backend(&dbus);

    if !name_has_owner(&dbus, SECRETS_NAME) {
        activate_backend(&dbus, installed)?;
    }

    // Identify who actually answered rather than trusting what is installed —
    // on a mixed system both may be present.
    let backend = running_backend(&dbus).unwrap_or(installed);

    // Connecting negotiates a DH session; if that works, the wallet is real.
    SecretService::connect(EncryptionType::Dh).map_err(|error| Unavailable::NotRunning {
        installed: backend,
        detail: error.to_string(),
    })?;

    let _ = DETECTED.set(backend);
    Ok(backend)
}

fn activate_backend(dbus: &DBusProxy, installed: Backend) -> Result<(), Unavailable> {
    let candidates = activatable_backends(dbus);
    if candidates.is_empty() {
        return Err(Unavailable::NotInstalled);
    }

    let mut last_error = String::from(t("no backend could be started"));
    let mut started = false;
    for name in &candidates {
        let Ok(well_known) = WellKnownName::try_from(name.as_str()) else {
            continue;
        };
        match dbus.start_service_by_name(well_known, 0) {
            Ok(_) => {
                started = true;
                break;
            }
            Err(error) => last_error = format!("{name}: {error}"),
        }
    }

    // Claiming the second name is not instantaneous after activation.
    if started {
        for _ in 0..20 {
            if name_has_owner(dbus, SECRETS_NAME) {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        last_error = tf!("started, but never claimed {}", SECRETS_NAME);
    }

    Err(match installed {
        Backend::Unknown => Unavailable::NotInstalled,
        installed => Unavailable::NotRunning {
            installed,
            detail: last_error,
        },
    })
}

/// The vault key for this data directory, or `None` on a first run.
///
/// The directory is part of the lookup so two Typeon profiles cannot end up
/// fighting over one wallet entry.
pub fn load_key(data_dir: &str) -> Result<Option<[u8; 32]>, String> {
    let service = connect()?;
    let collection = unlocked_collection(&service)?;
    let items = collection
        .search_items(attributes(data_dir))
        .map_err(|error| tf!("could not search the wallet: {}", error))?;

    let Some(item) = items.first() else {
        return Ok(None);
    };
    // The collection is unlocked above, but an individual item can carry its
    // own lock; reading a locked one fails in a way that looks like data loss.
    item.ensure_unlocked()
        .map_err(|error| tf!("the vault key entry stayed locked: {}", error))?;
    let mut secret = item
        .get_secret()
        .map_err(|error| tf!("could not read the vault key: {}", error))?;

    let key: Result<[u8; 32], String> = secret
        .as_slice()
        .try_into()
        .map_err(|_| t("the stored vault key is not 32 bytes").to_string());
    secret.zeroize();
    key.map(Some)
}

pub fn store_key(data_dir: &str, key: &[u8; 32]) -> Result<(), String> {
    let service = connect()?;
    let collection = unlocked_collection(&service)?;
    collection
        .create_item(
            ITEM_LABEL,
            attributes(data_dir),
            key,
            // Replace: re-sealing must not leave the previous key sitting in
            // the wallet next to the new one.
            true,
            "application/octet-stream",
        )
        .map_err(|error| tf!("could not write the vault key: {}", error))?;
    Ok(())
}

/// Removes this profile's vault key. Used by "log out", which must not leave a
/// key behind for a data directory that no longer exists.
pub fn delete_key(data_dir: &str) -> Result<(), String> {
    let service = connect()?;
    let collection = unlocked_collection(&service)?;
    let items = collection
        .search_items(attributes(data_dir))
        .map_err(|error| tf!("could not search the wallet: {}", error))?;
    for item in &items {
        item.delete()
            .map_err(|error| tf!("could not remove the vault key: {}", error))?;
    }
    Ok(())
}

fn connect<'a>() -> Result<SecretService<'a>, String> {
    SecretService::connect(EncryptionType::Dh)
        .map_err(|error| tf!("could not reach the system keyring: {}", error))
}

/// The default collection, unlocked — prompting the user if the wallet is
/// closed. Everything goes through here because a locked wallet reports "not
/// found" instead of "locked", which would look exactly like a lost key.
fn unlocked_collection<'a>(
    service: &'a SecretService<'a>,
) -> Result<secret_service::blocking::Collection<'a>, String> {
    let collection = service
        .get_default_collection()
        .map_err(|error| tf!("no default wallet collection: {}", error))?;
    collection
        .unlock()
        .map_err(|error| tf!("the wallet stayed locked: {}", error))?;
    Ok(collection)
}

fn attributes(data_dir: &str) -> HashMap<&str, &str> {
    HashMap::from([
        ("application", ATTR_APPLICATION),
        ("key", ATTR_KEY),
        ("profile", data_dir),
    ])
}

fn name_has_owner(dbus: &DBusProxy, name: &str) -> bool {
    BusName::try_from(name)
        .ok()
        .and_then(|name| dbus.name_has_owner(name).ok())
        .unwrap_or(false)
}

/// Backend names D-Bus knows how to start on this machine.
fn activatable_backends(dbus: &DBusProxy) -> Vec<String> {
    let Ok(names) = dbus.list_activatable_names() else {
        return Vec::new();
    };
    let names: Vec<String> = names.into_iter().map(|name| name.to_string()).collect();
    BACKEND_NAMES
        .iter()
        .filter(|candidate| names.iter().any(|name| name == *candidate))
        .map(|candidate| (*candidate).to_string())
        .collect()
}

/// Which wallet is installed, from the activatable names alone — this works
/// even when nothing is running yet.
fn installed_backend(dbus: &DBusProxy) -> Backend {
    for name in activatable_backends(dbus) {
        if name.starts_with("org.kde.") {
            return Backend::KdeWallet;
        }
        if name.starts_with("org.gnome.") {
            return Backend::GnomeKeyring;
        }
    }
    Backend::Unknown
}

/// Which wallet actually owns the Secret Service name right now, identified by
/// the process behind the connection.
fn running_backend(dbus: &DBusProxy) -> Option<Backend> {
    let name = BusName::try_from(SECRETS_NAME).ok()?;
    let pid = dbus.get_connection_unix_process_id(name).ok()?;
    let command = std::fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
    let command = command.trim();
    if command.contains("ksecret") || command.contains("kwallet") {
        Some(Backend::KdeWallet)
    } else if command.contains("keyring") {
        Some(Backend::GnomeKeyring)
    } else {
        None
    }
}
