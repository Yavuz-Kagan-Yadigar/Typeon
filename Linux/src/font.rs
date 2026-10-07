//! Custom font loading — the desktop counterpart of Android's `FontOverride` +
//! `ThemePrefs.CustomFont`.
//!
//! ## How it works
//!
//! 1. A user picks a `.ttf`/`.otf` file via the settings file picker.
//!    The file is copied into the app's data directory
//!    (`$XDG_DATA_HOME/typeon/`).
//! 2. On every `apply_theme` call the `FontManager` scans the data directory,
//!    loads every `.ttf`/`.otf` it finds, registers the font(s) with the
//!    system font database (`fontdb` → fontconfig), and extracts the CSS-safe
//!    family name from each file.
//! 3. `Appearance.custom_font_family` carries the active family name into the
//!    CSS generator, which injects it as `font-family: local("Family Name");`
//!    so the *entire* app (including stock libadwaita widgets) uses it.
//!
//! This mirrors the Android flow:
//! - `SettingsFragment.onFontPicked` → copies file, registers it.
//! - `FontOverride.applyFile` → replaces Android's default `Typeface` via
//!   reflection so *every* `TextView` uses the custom font.

use std::path::PathBuf;

/// A single imported font, keyed by a timestamp-based id (epoch-ms).
#[derive(Debug, Clone)]
pub struct CustomFont {
    /// Unique id (epoch-ms timestamp) — used as the file name prefix.
    pub id: String,
    /// Original file display name (e.g. "Fira Code").
    pub display_name: String,
    /// Absolute path to the `.ttf`/`.otf` file.
    pub path: PathBuf,
    /// CSS `font-family` name extracted from the font file.
    pub family_name: String,
}

/// Font manager — tracks all imported fonts and the active one.
pub struct FontManager {
    data_dir: PathBuf,
    /// All loaded custom fonts, keyed by id.
    custom_fonts: std::collections::HashMap<String, CustomFont>,
    /// Id of the currently active custom font.
    active_id: Option<String>,
}

impl FontManager {
    pub fn new(data_dir: PathBuf) -> Self {
        Self {
            data_dir,
            custom_fonts: std::collections::HashMap::new(),
            active_id: None,
        }
    }

    /// Register the active custom font with the system font database and return
    /// its CSS family name (if any).
    ///
    /// This must be called **before** applying the theme stylesheet.
    pub fn register_active(&mut self) -> Option<String> {
        if let Some(id) = &self.active_id {
            if let Some(font) = self.custom_fonts.get(id) {
                let name = &font.family_name;
                log::debug!(
                    "register_active: font family={name} path={}",
                    font.path.display()
                );
                return Some(name.clone());
            }
        }
        None
    }

    /// Set which custom font is currently active (by id).
    pub fn set_active(&mut self, id: Option<String>) {
        self.active_id = id;
    }

    /// Discover all `.ttf`/`.otf` files in the data directory, load them with
    /// fontdb, and return them sorted by id (oldest first).
    ///
    /// Returns a list of discovered fonts (for the settings UI to show in the
    /// font selector combo box).
    pub fn discover(&mut self) -> Vec<CustomFont> {
        self.custom_fonts.clear();

        let mut db = fontdb::Database::new();
        // Load system fonts so custom fonts are merged in, not replacing them.
        db.load_system_fonts();

        // Collect font files from the data directory.
        let font_files: Vec<PathBuf> = if self.data_dir.is_dir() {
            std::fs::read_dir(&self.data_dir)
                .ok()
                .into_iter()
                .flatten()
                .filter_map(|e| e.ok())
                .filter(|e| {
                    let path = e.path();
                    let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("").to_string();
                    ext == "ttf" || ext == "otf"
                })
                .map(|e| e.path())
                .collect()
        } else {
            Vec::new()
        };

        // Load each font file into fontdb and extract family names.
        for file in &font_files {
            // Load into fontdb so fontconfig can resolve it.
            let _ = db.load_font_file(file);
        }

        // Now iterate all loaded faces and match by file path.
        for file in &font_files {
            let family_name = db
                .faces()
                .find(|face| match &face.source {
                    fontdb::Source::File(path) => path == file,
                    _ => false,
                })
                .and_then(|face| {
                    face.families
                        .first()
                        .map(|f: &(String, fontdb::Language)| f.0.clone())
                })
                .unwrap_or_else(|| {
                    // Fallback: use the file stem as the family name.
                    file.file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("Custom")
                        .trim_start_matches("custom_font_")
                        .to_string()
                });

            let id = file
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown")
                .trim_start_matches("custom_font_")
                .to_string();

            let display_name = id.clone();

            self.custom_fonts.insert(
                id.clone(),
                CustomFont {
                    id,
                    display_name,
                    path: file.clone(),
                    family_name,
                },
            );
        }

        // Sort by id (oldest first, since ids are epoch-ms timestamps).
        let mut fonts: Vec<CustomFont> = self.custom_fonts.values().cloned().collect();
        fonts.sort_by(|a, b| a.id.cmp(&b.id));
        fonts
    }
}
