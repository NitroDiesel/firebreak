//! Translations, from the C build's language file (bin/simplewall.lng, 29
//! languages). Its entries are keyed by string id; resources/i18n/english.ini
//! has the English text for each id, taken from the C build's resource.rc. A
//! UI string is translated when it is worded exactly as in the original; other
//! strings stay English.

use std::collections::HashMap;
use std::sync::RwLock;

const LANGUAGES: &str = include_str!("../resources/i18n/simplewall.lng");
const ENGLISH: &str = include_str!("../resources/i18n/english.ini");

/// Sections whose ids do not match the C build's (Armenian is shifted upstream:
/// its "File" entry says "No updates available.").
const BROKEN: &[&str] = &["Armenian"];

/// English text to translated text for the chosen language. Leaked on purpose:
/// one small table per language switch, so lookups can hand out `&'static str`.
static TABLE: RwLock<Option<&'static HashMap<&'static str, &'static str>>> = RwLock::new(None);

/// "English" plus every usable language in the file.
pub fn languages() -> Vec<&'static str> {
    let mut out = vec!["English"];
    for line in LANGUAGES.lines() {
        if let Some(name) = line.trim().strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            if !BROKEN.contains(&name) {
                out.push(name);
            }
        }
    }
    out
}

/// Switch language. Unknown names and "English" use the built-in text.
pub fn set_language(name: &str) {
    let table = (!name.is_empty() && name != "English")
        .then(|| build(name))
        .filter(|t| !t.is_empty())
        .map(|t| &*Box::leak(Box::new(t)));
    *TABLE.write().unwrap() = table;
}

fn section(text: &'static str, name: &str) -> HashMap<&'static str, &'static str> {
    let header = format!("[{name}]");
    let mut inside = false;
    let mut out = HashMap::new();
    for line in text.lines() {
        let line = line.trim_start_matches('\u{feff}').trim_end_matches('\r');
        if line.starts_with('[') {
            inside = line.trim() == header;
            continue;
        }
        if !inside || line.starts_with(';') {
            continue;
        }
        if let Some((id, value)) = line.split_once('=') {
            out.insert(id.trim(), value);
        }
    }
    out
}

fn build(name: &str) -> HashMap<&'static str, &'static str> {
    let mut english: Vec<_> = section(ENGLISH, "English").into_iter().collect();
    // The same English text can have two ids (068 and 200 are both "Apps with
    // timer"); the lowest id wins, so the choice is stable.
    english.sort();
    let local = section(LANGUAGES, name);
    let mut out = HashMap::new();
    for (id, en) in english {
        if let Some(tr) = local.get(id).filter(|tr| !tr.is_empty() && *tr != &en) {
            out.entry(unescape(en)).or_insert(unescape(tr));
        }
    }
    out
}

/// resource.rc doubles quotes inside strings; the language file uses \n for line breaks.
fn unescape(text: &'static str) -> &'static str {
    if text.contains("\"\"") || text.contains("\\n") {
        Box::leak(text.replace("\"\"", "\"").replace("\\n", "\n").into_boxed_str())
    } else {
        text
    }
}

/// The translation of `english`, or `english` itself.
pub fn t(english: &'static str) -> &'static str {
    match *TABLE.read().unwrap() {
        Some(table) => table.get(english).copied().unwrap_or(english),
        None => english,
    }
}

/// `english` in English, but the translation of `original` (the C build's
/// wording of the same thing) in other languages.
pub fn t_as(original: &'static str, english: &'static str) -> &'static str {
    match *TABLE.read().unwrap() {
        Some(table) => table.get(original).copied().unwrap_or(english),
        None => english,
    }
}

/// Font files a language needs beyond Segoe UI, from the Windows font folder.
pub fn extra_fonts(name: &str) -> &'static [&'static str] {
    match name {
        "Chinese (Simplified)" => &["msyh.ttc"],
        "Chinese (Traditional)" => &["msjh.ttc"],
        "Japanese" => &["YuGothM.ttc", "meiryo.ttc"],
        "Korean" => &["malgun.ttf"],
        _ => &[],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn german_translates_original_wording_only() {
        assert!(languages().contains(&"German"));
        assert!(!languages().contains(&"Armenian"));
        let table = build("German");
        assert_eq!(table.get("File"), Some(&"Datei"));
        assert_eq!(table.get("Apps with timer"), Some(&"Apps mit Timer"));
        assert_eq!(table.get("A string the original never had"), None);
    }

    #[test]
    fn every_language_has_most_strings() {
        for name in languages().into_iter().skip(1) {
            assert!(build(name).len() > 50, "{name} has few translations");
        }
    }
}
