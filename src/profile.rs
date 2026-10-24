//! Profile load and save.
//! Internal rules come from the upstream `profile_internal.xml` (schema version 6).
//! The user profile is plain XML written by this port.

use std::fs;
use std::path::{Path, PathBuf};

use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;

use crate::model::{
    AppItem, AppKind, BlocklistGroup, BlocklistState, Direction, Profile, Rule, RuleAction,
    RuleOrigin, Settings, SYSTEM_APP,
};

const INTERNAL: &str = include_str!("../resources/profile_internal.xml");

pub fn load() -> Profile {
    let text = load_path().and_then(|path| fs::read_to_string(path).ok());
    from_user_text(text.as_deref())
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
    fs::write(&path, write_user(profile)).map_err(|e| e.to_string())?;
    Ok(path)
}

/// Where new settings are written.
///
/// Portable mode (`simplewall.ini` beside the exe) stays next to the exe.
/// Otherwise settings go to `%ProgramData%\simplewall-rust`. Administrator
/// Protection runs the elevated process under a shadow account, so
/// `%APPDATA%` from that process is not the profile that exists after reboot
/// (henrypp/simplewall#2163).
pub fn user_path() -> Option<PathBuf> {
    portable_path().or_else(program_data_path).or_else(appdata_path)
}

/// Newest file the user can still have: portable, then ProgramData, then the
/// old AppData location so an existing profile is not dropped.
fn load_path() -> Option<PathBuf> {
    [portable_path(), program_data_path(), appdata_path()]
        .into_iter()
        .flatten()
        .find(|path| path.exists())
}

fn portable_path() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    if dir.join("simplewall.ini").exists() {
        Some(dir.join("profile.xml"))
    } else {
        None
    }
}

fn program_data_path() -> Option<PathBuf> {
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
        if let Some(existing) = profile
            .rules
            .iter_mut()
            .find(|r| r.name == rule.name && r.origin == rule.origin)
        {
            existing.enabled = rule.enabled;
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
    for (key, val) in attrs(e) {
        match key.as_str() {
            "path" => app.path = val,
            "name" => app.display_name = val,
            "enabled" => app.enabled = is_true(&val),
            "timer" => app.timer_until = val.parse().unwrap_or(0),
            "comment" => app.comment = val,
            "pinned" => app.pinned = is_true(&val),
            "added" => app.added = val.parse().unwrap_or(0),
            "kind" => {
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
                    let flag = is_true(&val);
                    let state = BlocklistState::from_attr(&val);
                    match key.as_str() {
                        "allow_loopback" => settings.allow_loopback = flag,
                        "allow_ipv6" => settings.allow_ipv6 = flag,
                        "allow_lan" => settings.allow_lan = flag,
                        "user_allows_override_blocklist" => {
                            settings.user_allows_override_blocklist = flag
                        }
                        "log_to_file" => settings.log_to_file = flag,
                        "filters_temporary" => settings.filters_temporary = flag,
                        "always_on_top" => settings.always_on_top = flag,
                        "show_filenames_only" => settings.show_filenames_only = flag,
                        "log_ui" => settings.log_ui = flag,
                        "blocklist_spy" => {
                            settings.blocklist_spy = state.unwrap_or(settings.blocklist_spy)
                        }
                        "blocklist_update" => {
                            settings.blocklist_update = state.unwrap_or(settings.blocklist_update)
                        }
                        "blocklist_extra" => {
                            settings.blocklist_extra = state.unwrap_or(settings.blocklist_extra)
                        }
                        _ => {}
                    }
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
    let s = &profile.settings;
    xml.push_str(&format!(
        "\t<settings allow_loopback=\"{}\" allow_ipv6=\"{}\" allow_lan=\"{}\" user_allows_override_blocklist=\"{}\" log_to_file=\"{}\" filters_temporary=\"{}\" always_on_top=\"{}\" show_filenames_only=\"{}\" log_ui=\"{}\" blocklist_spy=\"{}\" blocklist_update=\"{}\" blocklist_extra=\"{}\" />\n",
        bool_attr(s.allow_loopback),
        bool_attr(s.allow_ipv6),
        bool_attr(s.allow_lan),
        bool_attr(s.user_allows_override_blocklist),
        bool_attr(s.log_to_file),
        bool_attr(s.filters_temporary),
        bool_attr(s.always_on_top),
        bool_attr(s.show_filenames_only),
        bool_attr(s.log_ui),
        s.blocklist_spy as u8,
        s.blocklist_update as u8,
        s.blocklist_extra as u8,
    ));
    xml.push_str("\t<apps>\n");
    for app in &profile.apps {
        xml.push_str(&format!(
            "\t\t<item path=\"{}\" name=\"{}\" enabled=\"{}\" timer=\"{}\" kind=\"{}\" pinned=\"{}\" added=\"{}\" comment=\"{}\" />\n",
            esc(&app.path),
            esc(&app.display_name),
            bool_attr(app.enabled),
            app.timer_until,
            kind_attr(app.kind),
            bool_attr(app.pinned),
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
        let default = defaults
            .iter()
            .find(|d| d.origin == rule.origin && d.name == rule.name)
            .map(|d| d.enabled);
        if default == Some(rule.enabled) {
            continue;
        }
        xml.push_str(&format!(
            "\t\t<item name=\"{}\" origin=\"{}\" is_enabled=\"{}\" />\n",
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
    fn old_phantom_rules_are_dropped() {
        let text = r#"<root><apps><item path="C:\x.exe" name="x.exe" enabled="false" /></apps>
            <rules_user><item name="x.exe" rule="" rule_local="" dir="0" protocol="0" action="allow" enabled="true" apps="" /></rules_user></root>"#;
        let loaded = from_user_text(Some(text));
        assert!(loaded.rules.iter().all(|r| r.origin != RuleOrigin::User));
    }
}
