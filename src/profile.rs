//! Profile load and save.
//! Internal rules come from the upstream `profile_internal.xml` (schema version 6).
//! The user profile is plain XML written by this port.

use std::fs;
use std::path::{Path, PathBuf};

use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;

use crate::model::{
    AppItem, AppKind, BlocklistGroup, Direction, Profile, Rule, RuleAction,
    RuleOrigin, Settings, SYSTEM_APP,
};

const INTERNAL: &str = include_str!("../resources/profile_internal.xml");

pub fn load() -> Profile {
    // A damaged profile falls back to the backup, as `_app_profile_load` does.
    let read = |path: PathBuf| {
        let text = crate::swc::decode(&fs::read(path).ok()?).ok()?;
        text.contains("<root").then_some(text)
    };
    let text = load_path().and_then(|path| read(path.clone()).or_else(|| read(backup_path(&path))));
    from_user_text(text.as_deref())
}

/// `profile.xml.bak` next to the profile.
fn backup_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".bak");
    PathBuf::from(name)
}

/// How long a backup is kept before the next save refreshes it (BACKUP_HOURS_PERIOD).
const BACKUP_PERIOD: std::time::Duration = std::time::Duration::from_secs(24 * 60 * 60);

/// What an import brought in.
pub struct Imported {
    pub apps: usize,
    pub rules: usize,
    /// The file came from the C build, not this port.
    pub from_original: bool,
}

/// Replace the apps and rules with a profile file's: this port's own, or the
/// C build's (plain, compressed, or encrypted). Settings are kept unless the
/// file is this port's, since the C build keeps them in simplewall.ini.
pub fn import(profile: &mut Profile, bytes: &[u8]) -> Result<Imported, String> {
    let text = crate::swc::decode(bytes)?;
    if !text.contains("<root") {
        return Err("This is not a Firebreak or simplewall profile.".into());
    }
    let ours = text.contains("<settings") || text.contains("<rules_user");
    let imported = if ours {
        from_user_text(Some(&text))
    } else {
        let mut imported = Profile {
            rules: default_rules(&profile.settings),
            settings: profile.settings.clone(),
            ..Profile::default()
        };
        // The C build's user rules are in rules_custom; they are this port's user rules.
        let text = text.replace("<rules_custom", "<rules_user").replace("</rules_custom", "</rules_user");
        merge_user(&mut imported, &text);
        for rule in imported.rules.iter_mut().filter(|r| r.origin == RuleOrigin::User) {
            rule.readonly = false;
        }
        imported
    };
    let result = Imported {
        apps: imported.apps.len(),
        rules: imported.rules.iter().filter(|r| r.origin == RuleOrigin::User).count(),
        from_original: !ours,
    };
    *profile = imported;
    Ok(result)
}

/// Write this port's profile format to `path`.
pub fn export(profile: &Profile, path: &Path) -> Result<(), String> {
    fs::write(path, write_user(profile)).map_err(|e| e.to_string())
}

/// The C build's profile, if it was ever used on this machine:
/// `%APPDATA%\Henry++\simplewall\profile.xml`.
pub fn original_profile_path() -> Option<PathBuf> {
    let appdata = std::env::var_os("APPDATA")?;
    let path = PathBuf::from(appdata).join("Henry++").join("simplewall").join("profile.xml");
    path.exists().then_some(path)
}

/// True when this port has never saved a profile on this machine.
pub fn is_first_run() -> bool {
    load_path().is_none()
}

fn from_user_text(text: Option<&str>) -> Profile {
    let settings = text.map(parse_settings).unwrap_or_default();
    let mut profile = Profile {
        rules: default_rules(&settings),
        settings,
        ..Profile::default()
    };
    if let Some(text) = text {
        merge_user(&mut profile, text);
    }
    profile
}

pub fn save(profile: &Profile) -> Result<PathBuf, String> {
    let path = user_path().ok_or_else(|| "could not resolve a profile directory".to_string())?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    // Keep a day-old copy to fall back to (IsBackupProfile).
    let backup = backup_path(&path);
    let stale = fs::metadata(&backup)
        .and_then(|m| m.modified())
        .map_or(true, |t| t.elapsed().unwrap_or_default() >= BACKUP_PERIOD);
    if stale && path.exists() {
        let _ = fs::copy(&path, &backup);
    }
    // Write beside and rename, so a crash mid-write cannot leave half a profile.
    let temp = path.with_extension("xml.tmp");
    let format = crate::swc::Format::from_setting(profile.settings.profile_type);
    let bytes = crate::swc::encode(&write_user(profile), format)?;
    fs::write(&temp, bytes).map_err(|e| e.to_string())?;
    fs::rename(&temp, &path).map_err(|e| e.to_string())?;
    Ok(path)
}

/// Where new settings are written.
///
/// Portable mode (`firebreak.ini` beside the exe) stays next to the exe.
/// Otherwise settings go to `%ProgramData%\Firebreak`. Administrator
/// Protection runs the elevated process under a shadow account, so
/// `%APPDATA%` from that process is not the profile that exists after reboot
/// (henrypp/simplewall#2163).
pub fn user_path() -> Option<PathBuf> {
    portable_path().or_else(program_data_path)
}

/// Newest file the user can still have: portable, then ProgramData, then the
/// folders older versions used, so an existing profile is not dropped.
fn load_path() -> Option<PathBuf> {
    migrate_legacy();
    [portable_path(), program_data_path(), legacy_program_data_path(), appdata_path()]
        .into_iter()
        .flatten()
        .find(|path| path.exists())
}

/// Before the rename to Firebreak (4.0), settings were in
/// `%ProgramData%\simplewall-rust`. Move them over once. Only administrators
/// can write either folder, so a start without elevation reads the old one.
fn migrate_legacy() {
    let (Some(new), Some(old)) = (program_data_path(), legacy_program_data_path()) else {
        return;
    };
    if portable_path().is_some() || new.exists() || !old.exists() || !crate::wfp::is_admin() {
        return;
    }
    let (Some(new_dir), Some(old_dir)) = (new.parent(), old.parent()) else {
        return;
    };
    if fs::create_dir_all(new_dir).is_err() {
        return;
    }
    for file in [old.clone(), backup_path(&old)] {
        let Some(name) = file.file_name() else { continue };
        if file.exists() && fs::copy(&file, new_dir.join(name)).is_err() {
            return;
        }
    }
    let _ = fs::remove_dir_all(old_dir);
}

fn portable_path() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    if dir.join("firebreak.ini").exists() {
        Some(dir.join("profile.xml"))
    } else {
        None
    }
}

fn program_data_path() -> Option<PathBuf> {
    let base = std::env::var_os("ProgramData")?;
    Some(PathBuf::from(base).join("Firebreak").join("profile.xml"))
}

fn legacy_program_data_path() -> Option<PathBuf> {
    let base = std::env::var_os("ProgramData")?;
    Some(PathBuf::from(base).join("simplewall-rust").join("profile.xml"))
}

fn appdata_path() -> Option<PathBuf> {
    let appdata = std::env::var_os("APPDATA")?;
    Some(PathBuf::from(appdata).join("simplewall-rust").join("profile.xml"))
}

/// Internal rules with blocklist group states applied. This is also the
/// baseline `rules_config` is written against.
fn default_rules(settings: &Settings) -> Vec<Rule> {
    let mut profile = Profile {
        rules: parse_rules(INTERNAL, true),
        settings: settings.clone(),
        ..Profile::default()
    };
    for rule in &mut profile.rules {
        // Blocklist names outside the three groups are blocked, as in `_app_ruleblocklistsetstate`.
        if rule.origin == RuleOrigin::Blocklist && BlocklistGroup::of(&rule.name).is_none() {
            rule.enabled = true;
            rule.action = RuleAction::Block;
        }
    }
    for group in BlocklistGroup::all() {
        profile.apply_blocklist(group);
    }
    profile.rules
}

fn merge_user(profile: &mut Profile, text: &str) {
    for rule in parse_rules(text, false) {
        if rule.origin == RuleOrigin::User {
            // Older builds read <apps> items as rules and saved them back as
            // empty user rules. A rule with no address, protocol, or app matches nothing.
            if !is_empty_rule(&rule) {
                profile.rules.push(rule);
            }
            continue;
        }
        // The C build's rules_config has no origin attribute; match any built-in rule by name.
        let index = profile
            .rules
            .iter()
            .position(|r| r.name == rule.name && r.origin == rule.origin)
            .or_else(|| profile.rules.iter().position(|r| r.name == rule.name && r.origin != RuleOrigin::User));
        if let Some(existing) = index.map(|i| &mut profile.rules[i]) {
            existing.enabled = rule.enabled;
            // Apps assigned to a built-in rule, as the C build's rules_config allows.
            if !rule.apps.is_empty() {
                existing.apps = rule.apps;
            }
        }
    }
    profile.apps = parse_apps(text);
}

fn is_empty_rule(rule: &Rule) -> bool {
    rule.remote.trim().is_empty()
        && rule.local.trim().is_empty()
        && rule.apps.is_empty()
        && rule.protocol == 0
        && !rule.services
        && !rule.kernel
}

fn attrs(e: &BytesStart) -> Vec<(String, String)> {
    e.attributes()
        .flatten()
        .map(|attr| {
            let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
            let val = attr.unescape_value().map(|v| v.to_string()).unwrap_or_default();
            (key, val)
        })
        .collect()
}

/// Reads `<item>` elements inside the rule sections only. `<apps>` items are not rules.
fn parse_rules(text: &str, internal: bool) -> Vec<Rule> {
    let mut reader = Reader::from_str(text);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();
    let mut section: Option<RuleOrigin> = None;
    let mut rules = Vec::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                section = match e.name().as_ref() {
                    b"rules_system" => Some(RuleOrigin::System),
                    b"rules_blocklist" => Some(RuleOrigin::Blocklist),
                    b"rules_custom" => Some(RuleOrigin::Custom),
                    b"rules_user" => Some(RuleOrigin::User),
                    // Only the enabled state of internal rules, keyed by name and origin.
                    b"rules_config" => Some(RuleOrigin::System),
                    b"item" => {
                        if let Some(origin) = section {
                            rules.extend(rule_from(&e, origin, internal));
                        }
                        section
                    }
                    _ => None,
                };
            }
            Ok(Event::Empty(e)) if e.name().as_ref() == b"item" => {
                if let Some(origin) = section {
                    rules.extend(rule_from(&e, origin, internal));
                }
            }
            Ok(Event::End(e)) if e.name().as_ref().starts_with(b"rules_") => section = None,
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
        buf.clear();
    }
    rules
}

fn rule_from(e: &BytesStart, section: RuleOrigin, internal: bool) -> Option<Rule> {
    let mut rule = Rule {
        name: String::new(),
        remote: String::new(),
        local: String::new(),
        direction: Direction::Outbound,
        action: RuleAction::Permit,
        protocol: 0,
        enabled: false,
        origin: section,
        apps: Vec::new(),
        services: false,
        kernel: false,
        readonly: true,
    };
    for (key, val) in attrs(e) {
        match key.as_str() {
            "name" => rule.name = val,
            "rule" | "rule_remote" => rule.remote = val,
            "rule_local" => rule.local = val,
            "dir" => rule.direction = Direction::from_attr(val.parse().unwrap_or(0)),
            "protocol" => rule.protocol = val.parse().unwrap_or(0),
            "is_enabled" | "enabled" => rule.enabled = is_true(&val),
            "apps" => rule.apps = split_apps(&val),
            "is_services" | "services" => rule.services = is_true(&val),
            "is_kernel" | "kernel" => rule.kernel = is_true(&val),
            // The C build marks block rules with is_block instead of action.
            "is_block" if !internal && is_true(&val) => rule.action = RuleAction::Block,
            "action" if !internal => {
                rule.action = if val.eq_ignore_ascii_case("block") {
                    RuleAction::Block
                } else {
                    RuleAction::Permit
                };
            }
            "origin" if !internal => {
                rule.origin = match val.as_str() {
                    "system" => RuleOrigin::System,
                    "blocklist" => RuleOrigin::Blocklist,
                    "custom" => RuleOrigin::Custom,
                    _ => RuleOrigin::User,
                };
            }
            _ => {}
        }
    }
    if internal && rule.origin == RuleOrigin::Blocklist {
        rule.action = RuleAction::Block;
    }
    rule.readonly = rule.origin != RuleOrigin::User;
    (!rule.name.is_empty()).then_some(rule)
}

fn parse_apps(text: &str) -> Vec<AppItem> {
    let mut reader = Reader::from_str(text);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();
    let mut in_apps = false;
    let mut apps = Vec::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) if e.name().as_ref() == b"apps" => in_apps = true,
            Ok(Event::End(e)) if e.name().as_ref() == b"apps" => in_apps = false,
            Ok(Event::Empty(e)) if in_apps && e.name().as_ref() == b"item" => {
                apps.extend(app_from(&e));
            }
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
        buf.clear();
    }
    apps
}

fn app_from(e: &BytesStart) -> Option<AppItem> {
    let mut app = AppItem::new(String::new(), String::new(), AppKind::Regular);
    app.added = 0;
    let mut kind_set = false;
    // Attribute names of this port, and of the C build's profile (is_enabled,
    // is_silent, is_undeletable, timestamp) for imports.
    for (key, val) in attrs(e) {
        match key.as_str() {
            "path" => app.path = val,
            "name" => app.display_name = val,
            "enabled" | "is_enabled" => app.enabled = is_true(&val),
            "timer" => app.timer_until = val.parse().unwrap_or(0),
            "comment" => app.comment = val,
            "pinned" | "is_undeletable" => app.pinned = is_true(&val),
            "silent" | "is_silent" => app.silent = is_true(&val),
            "hash" => app.hash = val,
            "added" | "timestamp" => app.added = val.parse().unwrap_or(0),
            "kind" => {
                kind_set = true;
                app.kind = match val.as_str() {
                    "service" => AppKind::Service,
                    "system" => AppKind::System,
                    "uwp" => AppKind::Uwp,
                    _ => AppKind::Regular,
                }
            }
            _ => {}
        }
    }
    if app.path.is_empty() {
        return None;
    }
    if !kind_set {
        app.kind = kind_of_path(&app.path);
        if app.kind == AppKind::Regular {
            app.path = crate::apps::expand_env(&app.path);
        }
    }
    // A timer that ran out while the program was closed.
    if app.timer_until != 0 && app.timer_until <= crate::model::now_unix() {
        app.timer_until = 0;
        app.enabled = false;
    }
    // Earlier builds keyed kernel traffic on ntoskrnl.exe. WFP calls it "System".
    if app.kind == AppKind::System {
        app.path = SYSTEM_APP.into();
        app.display_name = SYSTEM_APP.into();
    }
    // Earlier builds keyed services by image path, so every svchost service
    // shared one entry. Keep a permitted image as a plain app; drop the rest.
    if app.kind == AppKind::Service && app.path.contains('\\') {
        if !app.enabled {
            return None;
        }
        app.kind = AppKind::Regular;
    }
    if app.display_name.is_empty() {
        app.display_name = Path::new(&app.path)
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| app.path.clone());
    }
    Some(app)
}

fn parse_settings(text: &str) -> Settings {
    let mut settings = Settings::default();
    let mut reader = Reader::from_str(text);
    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Empty(e)) if e.name().as_ref() == b"settings" => {
                for (key, val) in attrs(&e) {
                    settings.set_attr(&key, &val);
                }
                break;
            }
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
        buf.clear();
    }
    settings
}

fn write_user(profile: &Profile) -> String {
    let mut xml = String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<root version=\"6\">\n");
    xml.push_str("\t<settings");
    for (key, value) in profile.settings.attrs() {
        xml.push_str(&format!(" {key}=\"{}\"", esc(&value)));
    }
    xml.push_str(" />\n");
    xml.push_str("\t<apps>\n");
    for app in &profile.apps {
        xml.push_str(&format!(
            "\t\t<item path=\"{}\" name=\"{}\" enabled=\"{}\" timer=\"{}\" kind=\"{}\" pinned=\"{}\" silent=\"{}\" hash=\"{}\" added=\"{}\" comment=\"{}\" />\n",
            esc(&app.path),
            esc(&app.display_name),
            bool_attr(app.enabled),
            app.timer_until,
            kind_attr(app.kind),
            bool_attr(app.pinned),
            bool_attr(app.silent),
            esc(&app.hash),
            app.added,
            esc(&app.comment)
        ));
    }
    xml.push_str("\t</apps>\n\t<rules_user>\n");
    for rule in profile.rules.iter().filter(|r| r.origin == RuleOrigin::User) {
        xml.push_str(&rule_item(rule));
    }
    // Only internal rules the user switched away from their default, so a
    // blocklist group change is not pinned by 1500 stale entries.
    xml.push_str("\t</rules_user>\n\t<rules_config>\n");
    let defaults = default_rules(&profile.settings);
    for rule in profile.rules.iter().filter(|r| r.origin != RuleOrigin::User) {
        let default = defaults.iter().find(|d| d.origin == rule.origin && d.name == rule.name);
        if default.is_some_and(|d| d.enabled == rule.enabled && d.apps == rule.apps) {
            continue;
        }
        let apps_changed = default.is_none_or(|d| d.apps != rule.apps);
        let apps = if apps_changed && !rule.apps.is_empty() {
            format!(" apps=\"{}\"", esc(&rule.apps.join("|")))
        } else {
            String::new()
        };
        xml.push_str(&format!(
            "\t\t<item name=\"{}\" origin=\"{}\" is_enabled=\"{}\"{apps} />\n",
            esc(&rule.name),
            origin_attr(rule.origin),
            bool_attr(rule.enabled)
        ));
    }
    xml.push_str("\t</rules_config>\n</root>\n");
    xml
}

fn rule_item(rule: &Rule) -> String {
    format!(
        "\t\t<item name=\"{}\" rule=\"{}\" rule_local=\"{}\" dir=\"{}\" protocol=\"{}\" action=\"{}\" enabled=\"{}\" apps=\"{}\" services=\"{}\" kernel=\"{}\" />\n",
        esc(&rule.name),
        esc(&rule.remote),
        esc(&rule.local),
        rule.direction as u8,
        rule.protocol,
        if rule.action == RuleAction::Block { "block" } else { "allow" },
        bool_attr(rule.enabled),
        esc(&rule.apps.join("|")),
        bool_attr(rule.services),
        bool_attr(rule.kernel)
    )
}

/// The C build's profile does not store a kind: it is "System", a package SID,
/// a service name (no backslash), or a file path.
fn kind_of_path(path: &str) -> AppKind {
    if path.eq_ignore_ascii_case(SYSTEM_APP) {
        AppKind::System
    } else if path.to_ascii_uppercase().starts_with("S-1-15-") {
        AppKind::Uwp
    } else if !path.contains('\\') && !path.contains('/') {
        AppKind::Service
    } else {
        AppKind::Regular
    }
}

fn split_apps(raw: &str) -> Vec<String> {
    raw.split('|')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn is_true(v: &str) -> bool {
    matches!(v.to_ascii_lowercase().as_str(), "true" | "1" | "yes")
}

fn bool_attr(v: bool) -> &'static str {
    if v { "true" } else { "false" }
}

fn kind_attr(kind: AppKind) -> &'static str {
    match kind {
        AppKind::Regular => "regular",
        AppKind::Service => "service",
        AppKind::System => "system",
        AppKind::Uwp => "uwp",
    }
}

fn origin_attr(origin: RuleOrigin) -> &'static str {
    match origin {
        RuleOrigin::System => "system",
        RuleOrigin::Blocklist => "blocklist",
        RuleOrigin::Custom => "custom",
        RuleOrigin::User => "user",
    }
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_rules_load() {
        let rules = default_rules(&Settings::default());
        assert!(rules.len() > 20);
        let dns = rules.iter().find(|r| r.name == "DNS").unwrap();
        assert!(dns.enabled);
        assert_eq!(dns.protocol, 17);
    }

    #[test]
    fn blocklist_defaults_block_spy_only() {
        let rules = default_rules(&Settings::default());
        let group = |prefix: &str| {
            rules
                .iter()
                .filter(|r| r.origin == RuleOrigin::Blocklist && r.name.starts_with(prefix))
                .collect::<Vec<_>>()
        };
        assert!(group("spy_").iter().all(|r| r.enabled && r.action == RuleAction::Block));
        assert!(group("extra_").iter().all(|r| !r.enabled));
        assert!(!group("spy_").is_empty());
    }

    #[test]
    fn saved_apps_are_not_read_as_rules() {
        let mut profile = from_user_text(None);
        let mut app = AppItem::new(r"C:\a\b.exe".into(), "b.exe".into(), AppKind::Regular);
        app.enabled = true;
        profile.apps.push(app);
        profile.rules.push(Rule {
            name: "web".into(),
            remote: "443".into(),
            local: String::new(),
            direction: Direction::Outbound,
            action: RuleAction::Permit,
            protocol: 6,
            enabled: true,
            origin: RuleOrigin::User,
            apps: vec![r"C:\a\b.exe".into()],
            services: false,
            kernel: false,
            readonly: false,
        });
        let first = write_user(&profile);
        let again = write_user(&from_user_text(Some(&first)));
        assert_eq!(first, again);
        let loaded = from_user_text(Some(&again));
        let user: Vec<_> = loaded.rules.iter().filter(|r| r.origin == RuleOrigin::User).collect();
        assert_eq!(user.len(), 1);
        assert_eq!(loaded.apps.len(), 1);
        assert!(loaded.apps[0].enabled);
    }

    #[test]
    fn rule_overrides_survive_a_round_trip() {
        let mut profile = from_user_text(None);
        let dns = profile.rules.iter_mut().find(|r| r.name == "DNS").unwrap();
        dns.enabled = false;
        let loaded = from_user_text(Some(&write_user(&profile)));
        assert!(!loaded.rules.iter().find(|r| r.name == "DNS").unwrap().enabled);
    }

    #[test]
    fn imports_the_c_build_profile() {
        let text = r#"<?xml version="1.0" encoding="utf-8"?>
<root timestamp="1" type="3" version="5">
	<apps>
		<item path="%SystemRoot%\system32\notepad.exe" timestamp="1700000000" is_enabled="true" is_silent="true" comment="hi" />
		<item path="System" is_enabled="true" />
		<item path="wuauserv" is_enabled="true" />
	</apps>
	<rules_custom>
		<item name="Web" rule="443" dir="0" protocol="6" apps="C:\a.exe" is_block="true" is_enabled="true" />
	</rules_custom>
	<rules_config>
		<item name="DNS" is_enabled="false" apps="C:\dns.exe" />
	</rules_config>
</root>"#;
        let mut profile = Profile::default();
        let result = import(&mut profile, text.as_bytes()).unwrap();
        assert!(result.from_original);
        assert_eq!((result.apps, result.rules), (3, 1));

        let notepad = &profile.apps[0];
        assert_eq!(notepad.kind, AppKind::Regular);
        assert!(!notepad.path.contains('%') && notepad.path.to_lowercase().ends_with(r"\system32\notepad.exe"));
        assert!(notepad.enabled && notepad.silent);
        assert_eq!((notepad.added, notepad.comment.as_str()), (1_700_000_000, "hi"));
        assert_eq!(profile.apps[1].kind, AppKind::System);
        assert_eq!(profile.apps[2].kind, AppKind::Service);

        let web = profile.rules.iter().find(|r| r.name == "Web").unwrap();
        assert_eq!((web.origin, web.action, web.protocol), (RuleOrigin::User, RuleAction::Block, 6));
        assert_eq!(web.apps, vec![r"C:\a.exe".to_string()]);
        assert!(!web.readonly);

        let dns = |p: &Profile| p.rules.iter().find(|r| r.name == "DNS" && r.origin != RuleOrigin::User).cloned().unwrap();
        assert!(!dns(&profile).enabled);
        assert_eq!(dns(&profile).apps, vec![r"C:\dns.exe".to_string()]);
        // The override, with its apps, survives this port's own save and load.
        let again = from_user_text(Some(&write_user(&profile)));
        assert_eq!(dns(&again).apps, dns(&profile).apps);
        assert!(!dns(&again).enabled);
    }

    #[test]
    fn old_phantom_rules_are_dropped() {
        let text = r#"<root><apps><item path="C:\x.exe" name="x.exe" enabled="false" /></apps>
            <rules_user><item name="x.exe" rule="" rule_local="" dir="0" protocol="0" action="allow" enabled="true" apps="" /></rules_user></root>"#;
        let loaded = from_user_text(Some(text));
        assert!(loaded.rules.iter().all(|r| r.origin != RuleOrigin::User));
    }
}
