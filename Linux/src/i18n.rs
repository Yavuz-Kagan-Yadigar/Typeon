//! UI translations. The English text is the key. `lang/<code>.json` maps it to
//! the translation; a missing entry shows the English text. The tables are
//! embedded, so Linux and Windows need no gettext. A language change applies
//! at the next start.

use std::collections::HashMap;
use std::fmt::Display;
use std::sync::OnceLock;

/// (code, name in its own language). The codes match the Android picker.
pub const LANGUAGES: &[(&str, &str)] = &[
    ("en", "English"),
    ("tr", "Türkçe"),
    ("es", "Español"),
    ("ru", "Русский"),
    ("uk", "Українська"),
    ("hi", "हिन्दी"),
    ("ar", "العربية"),
    ("zh-CN", "简体中文"),
];

fn source(code: &str) -> Option<&'static str> {
    Some(match code {
        "tr" => include_str!("lang/tr.json"),
        "es" => include_str!("lang/es.json"),
        "ru" => include_str!("lang/ru.json"),
        "uk" => include_str!("lang/uk.json"),
        "hi" => include_str!("lang/hi.json"),
        "ar" => include_str!("lang/ar.json"),
        "zh-CN" => include_str!("lang/zh-CN.json"),
        _ => return None,
    })
}

static TABLE: OnceLock<HashMap<String, String>> = OnceLock::new();

/// The language of the desktop session, from names such as `ru_RU.UTF-8`.
fn system_code(names: &[impl AsRef<str>]) -> &'static str {
    let first = names.first().map(|n| n.as_ref()).unwrap_or("en");
    let base = first.split(['_', '-', '.', '@']).next().unwrap_or("en");
    LANGUAGES.iter().map(|(c, _)| *c).find(|c| c.split('-').next() == Some(base)).unwrap_or("en")
}

/// Call once, before the first widget. `chosen = None` follows the system.
/// Returns the code in use.
pub fn init(chosen: Option<&str>) -> String {
    let code = match chosen {
        Some(code) => code.to_string(),
        None => system_code(&gtk::glib::language_names()).to_string(),
    };
    let table = source(&code).and_then(|json| serde_json::from_str(json).ok()).unwrap_or_default();
    let _ = TABLE.set(table);
    code
}

/// Translates a fixed text.
pub fn t(english: &'static str) -> &'static str {
    TABLE.get().and_then(|table| table.get(english)).map(String::as_str).unwrap_or(english)
}

/// Puts `args` into `{}` (in order) or `{0}`, `{1}` (a translation can move
/// them). `{{` and `}}` are literal braces.
pub fn fill(pattern: &str, args: &[&dyn Display]) -> String {
    let mut out = String::with_capacity(pattern.len());
    let mut chars = pattern.chars().peekable();
    let mut next = 0;
    while let Some(c) = chars.next() {
        match c {
            '{' | '}' if chars.peek() == Some(&c) => {
                chars.next();
                out.push(c);
            }
            '{' => {
                let index: String = std::iter::from_fn(|| chars.next_if(|d| d.is_ascii_digit())).collect();
                chars.next_if_eq(&'}');
                let index = index.parse().unwrap_or_else(|_| {
                    next += 1;
                    next - 1
                });
                if let Some(arg) = args.get(index) {
                    out.push_str(&arg.to_string());
                }
            }
            _ => out.push(c),
        }
    }
    out
}

/// `format!` for a translated pattern: `tf!("Edit failed: {}", error)`.
/// Only `{}` placeholders: format a number first if it needs a precision.
macro_rules! tf {
    ($pattern:literal $(, $arg:expr)* $(,)?) => {
        $crate::i18n::fill($crate::i18n::t($pattern), &[$(&$arg as &dyn std::fmt::Display),*])
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fills_in_order_and_by_index() {
        assert_eq!(fill("{} of {} {{x}}", &[&1, &2]), "1 of 2 {x}");
        assert_eq!(fill("{1}: {0}", &[&"a", &"b"]), "b: a");
    }

    #[test]
    fn system_language() {
        assert_eq!(system_code(&["ru_RU.UTF-8"]), "ru");
        assert_eq!(system_code(&["zh_CN"]), "zh-CN");
        assert_eq!(system_code(&["de_DE"]), "en");
    }

    #[test]
    fn every_table_parses_and_keeps_placeholders() {
        for (code, _) in &LANGUAGES[1..] {
            let table: HashMap<String, String> = serde_json::from_str(source(code).unwrap()).unwrap();
            for (key, value) in table {
                let count = |s: &str| s.replace("{{", "").matches('{').count();
                assert_eq!(count(&key), count(&value), "{code}: {key}");
            }
        }
    }
}
