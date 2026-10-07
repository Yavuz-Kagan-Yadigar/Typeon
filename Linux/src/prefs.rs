//! Local preferences — the desktop counterpart of the Android app's
//! SharedPreferences (`P2PService` node/Tor/storage keys, `ReadStatePrefs`,
//! `PinnedChatsPrefs`, `ThemePrefs`). One JSON file, rewritten on change;
//! these are all small, low-frequency settings.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Matches `P2PService.DEFAULT_HISTORY_STORAGE_LIMIT_BYTES`.
pub const DEFAULT_HISTORY_LIMIT_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Same bounds as `ThemePrefs` on Android, so the two clients feel identical.
pub const TEXT_SCALE_MIN: f64 = 0.70;
pub const TEXT_SCALE_MAX: f64 = 1.60;
pub const UI_SCALE_MIN: f64 = 0.75;
pub const UI_SCALE_MAX: f64 = 1.30;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Prefs {
    /// Spec 4.3 node mode — archive live traffic locally and relay for others.
    pub node_mode: bool,
    /// On by default, exactly as on Android: two devices behind CGNAT can
    /// reach each other out of the box. Only takes effect at `start_network`.
    pub tor_enabled: bool,
    pub history_storage_limit_bytes: u64,
    /// Conversation id -> last-read epoch ms. Key is the peer device
    /// fingerprint for 1:1, `"group:<id>"` for groups — the same convention
    /// the core uses for `read_state_sync` events.
    pub read_state: HashMap<String, u64>,
    /// Conversation ids pinned to the top of the chat list (same key form).
    pub pinned: HashSet<String>,
    /// `None` follows the desktop's light/dark preference.
    pub dark_mode: Option<bool>,
    /// `#rrggbb` seed for the Material 3 palette; `None` uses M3's own
    /// baseline seed. Every other colour role is derived from it.
    pub accent_color: Option<String>,
    /// `#rrggbb` window background override; `None` derives it from the seed.
    /// Container surfaces are stepped off whatever this ends up being.
    pub background_color: Option<String>,
    /// `#rrggbb` text colour override; `None` derives it from the seed.
    pub foreground_color: Option<String>,
    /// Font multiplier, same 0.70–1.60 range as the Android slider.
    pub text_scale: f64,
    /// Overall density multiplier, same 0.75–1.30 range as Android. Applied
    /// through `gtk-xft-dpi`, which is the toolkit's own scaling knob.
    pub ui_scale: f64,
    /// Remembered so the identity is not re-created on every launch when the
    /// user aborts linking halfway.
    pub device_name: String,
    /// True while this device is waiting to be adopted by an existing account.
    /// Set when the user picks "link to an existing device" and cleared once a
    /// primary adopts us — it is what lets a half-finished pairing resume on
    /// the next launch instead of dumping the user into an empty main window.
    /// A device created as its own account never sets it.
    pub awaiting_link: bool,
    /// Absolute path to a chat background image; `None` uses the plain surface.
    pub chat_wallpaper: Option<String>,
    /// CSS font family for the whole app; `None` follows the desktop font.
    pub font_family: Option<String>,
    /// Absolute paths to user-imported .ttf/.otf font files, keyed by a
    /// timestamp-based id. Values store the original file display name so
    /// the settings UI can show "Fira Code" instead of "custom_font_17249…".
    #[serde(default)]
    pub custom_fonts: HashMap<String, String>,
    /// Id of the custom font currently selected by the user; `None` means a
    /// built-in font or the system default is active.
    pub active_custom_font_id: Option<String>,

    #[serde(skip)]
    path: PathBuf,
    /// Set by the read-state helpers instead of writing immediately. Marking a
    /// conversation read happens on *every* arriving message, and rewriting
    /// the whole settings file that often is a lot of disk churn for something
    /// nobody misses if it lands a few seconds later. `flush` does the write.
    #[serde(skip)]
    dirty: bool,
}

impl Default for Prefs {
    fn default() -> Self {
        Self {
            node_mode: false,
            tor_enabled: true,
            history_storage_limit_bytes: DEFAULT_HISTORY_LIMIT_BYTES,
            read_state: HashMap::new(),
            pinned: HashSet::new(),
            dark_mode: None,
            accent_color: None,
            background_color: None,
            foreground_color: None,
            text_scale: 1.0,
            ui_scale: 1.0,
            device_name: String::new(),
            awaiting_link: false,
            chat_wallpaper: None,
            font_family: None,
            custom_fonts: HashMap::new(),
            active_custom_font_id: None,
            path: PathBuf::new(),
            dirty: false,
        }
    }
}

impl Prefs {
    pub fn load(dir: &Path) -> Self {
        let path = dir.join("settings.json");
        let mut prefs: Prefs = std::fs::read_to_string(&path)
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default();
        prefs.path = path;
        prefs
    }

    pub fn save(&self) {
        if self.path.as_os_str().is_empty() {
            return;
        }
        if let Ok(text) = serde_json::to_string_pretty(self) {
            // A failed write must not take the app down: the worst case is a
            // setting that does not survive a restart.
            let _ = std::fs::write(&self.path, text);
        }
    }

    pub fn is_pinned(&self, conversation_id: &str) -> bool {
        self.pinned.contains(conversation_id)
    }

    pub fn set_pinned(&mut self, conversation_id: &str, pinned: bool) {
        if pinned {
            self.pinned.insert(conversation_id.to_string());
        } else {
            self.pinned.remove(conversation_id);
        }
        self.save();
    }

    pub fn last_read_at(&self, conversation_id: &str) -> u64 {
        self.read_state.get(conversation_id).copied().unwrap_or(0)
    }

    pub fn mark_read_now(&mut self, conversation_id: &str) {
        self.mark_read_at(conversation_id, crate::util::now_ms());
    }

    /// Writes out anything the read-state helpers deferred. Called on a slow
    /// timer and when the window closes.
    pub fn flush(&mut self) {
        if self.dirty {
            self.save();
            self.dirty = false;
        }
    }

    /// Only ever moves forward — a sibling device's `read_state_sync` must not
    /// drag a conversation back to unread (see `ReadStatePrefs.markReadAt`).
    pub fn mark_read_at(&mut self, conversation_id: &str, timestamp_ms: u64) {
        if conversation_id.is_empty() || timestamp_ms == 0 {
            return;
        }
        let entry = self.read_state.entry(conversation_id.to_string()).or_insert(0);
        if timestamp_ms > *entry {
            *entry = timestamp_ms;
            self.dirty = true;
        }
    }
}
