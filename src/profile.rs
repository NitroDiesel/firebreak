//! Profile load and save.
//! Internal rules come from the upstream `profile_internal.xml` (schema version 6).
//! The user profile is plain XML written by this port.

use std::fs;
use std::path::{Path, PathBuf};

use quick_xml::events::Event;
use quick_xml::Reader;

use crate::model::{
    AppItem, AppKind, Direction, Profile, Rule, RuleAction, RuleOrigin, Settings,
};

const INTERNAL: &str = include_str!("../resources/profile_internal.xml");

pub fn load() -> Profile {
    let mut profile = Profile {
        rules: parse_internal(),
        ..Profile::default()
    };
    if let Some(path) = load_path() {
        if let Ok(text) = fs::read_to_string(&path) {
            merge_user(&mut profile, &text);
        }
    }
    profile
}

pub fn save(profile: &Profile) -> Result<PathBuf, String> {
    let path = user_path().ok_or_else(|| "could not resolve a profile directory".to_string())?;
    write_profile(&path, profile)?;
    Ok(path)
}

fn write_profile(path: &Path, profile: &Profile) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    fs::write(path, write_user(profile)).map_err(|e| e.to_string())
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

fn parse_internal() -> Vec<Rule> {
    parse_rules_xml(INTERNAL, true)
}

fn merge_user(profile: &mut Profile, text: &str) {
    let user_rules = parse_rules_xml(text, false);
    for rule in user_rules {
        if rule.origin == RuleOrigin::User {
            profile.rules.push(rule);
            continue;
        }
        if let Some(existing) = profile.rules.iter_mut().find(|r| r.name == rule.name && r.origin == rule.origin)
        {
            existing.enabled = rule.enabled;
        } else if let Some(existing) = profile.rules.iter_mut().find(|r| r.name == rule.name) {
            existing.enabled = rule.enabled;
        }
    }
    profile.apps = parse_apps(text);
    profile.settings = parse_settings(text);
}

fn parse_rules_xml(text: &str, internal: bool) -> Vec<Rule> {
    let mut reader = Reader::from_str(text);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();
    let mut section = RuleOrigin::User;
    let mut config_only = false;
    let mut rules = Vec::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                let tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                match tag.as_str() {
                    "rules_system" => {
                        section = RuleOrigin::System;
                        config_only = false;
                    }
                    "rules_blocklist" => {
                        section = RuleOrigin::Blocklist;
                        config_only = false;
                    }
                    "rules_custom" => {
                        section = RuleOrigin::Custom;
                        config_only = false;
                    }
                    "rules_user" => {
                        section = RuleOrigin::User;
                        config_only = false;
                    }
                    "rules_config" => {
                        section = RuleOrigin::System;
                        config_only = true;
                    }
                    "item" if is_rule_section(section, internal) || !internal => {
                        let mut name = String::new();
                        let mut remote = String::new();
                        let mut local = String::new();
                        let mut direction = Direction::Outbound;
                        let mut protocol = 0u8;
                        let mut enabled = false;
                        let mut apps = String::new();
                        let mut services = false;
                        let mut kernel = false;
                        let mut action = RuleAction::Permit;
                        let mut origin = section;
                        for attr in e.attributes().flatten() {
                            let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                            let val = attr
                                .unescape_value()
                                .map(|v| v.to_string())
                                .unwrap_or_default();
                            match key.as_str() {
                                "name" => name = val,
                                "rule" | "rule_remote" => remote = val,
                                "rule_local" => local = val,
                                "dir" => {
                                    direction = Direction::from_attr(val.parse().unwrap_or(0))
                                }
                                "protocol" => protocol = val.parse().unwrap_or(0),
                                "is_enabled" | "enabled" => enabled = is_true(&val),
                                "apps" => apps = val,
                                "is_services" | "services" => services = is_true(&val),
                                "is_kernel" | "kernel" => kernel = is_true(&val),
                                "action" => {
                                    action = if val.eq_ignore_ascii_case("block") {
                                        RuleAction::Block
                                    } else {
                                        RuleAction::Permit
                                    };
                                }
                                "origin" => {
                                    origin = match val.as_str() {
                                        "system" => RuleOrigin::System,
                                        "blocklist" => RuleOrigin::Blocklist,
                                        "custom" => RuleOrigin::Custom,
                                        _ => RuleOrigin::User,
                                    };
                                }
                                _ => {}
                            }
                        }
                        if internal {
                            origin = section;
                            action = if origin == RuleOrigin::Blocklist {
                                RuleAction::Block
                            } else {
                                RuleAction::Permit
                            };
                        }
                        let _ = config_only;
                        if !name.is_empty() {
                            rules.push(Rule {
                                name,
                                remote,
                                local,
                                direction,
                                action,
                                protocol,
                                enabled,
                                origin,
                                apps: split_apps(&apps),
                                services,
                                kernel,
                                readonly: origin != RuleOrigin::User,
                            });
                        }
                    }
                    _ => {}
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
        buf.clear();
    }
    rules
}

fn is_rule_section(section: RuleOrigin, internal: bool) -> bool {
    internal || section != RuleOrigin::User || true
}

fn parse_apps(text: &str) -> Vec<AppItem> {
    let mut reader = Reader::from_str(text);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();
    let mut in_apps = false;
    let mut apps = Vec::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                if e.name().as_ref() == b"apps" {
                    in_apps = true;
                }
            }
            Ok(Event::End(e)) => {
                if e.name().as_ref() == b"apps" {
                    in_apps = false;
                }
            }
            Ok(Event::Empty(e)) if in_apps && e.name().as_ref() == b"item" => {
                let mut path = String::new();
                let mut name = String::new();
                let mut enabled = false;
                let mut timer = 0u64;
                let mut comment = String::new();
                let mut pinned = false;
                let mut kind = AppKind::Regular;
                for attr in e.attributes().flatten() {
                    let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                    let val = attr.unescape_value().map(|v| v.to_string()).unwrap_or_default();
                    match key.as_str() {
                        "path" => path = val,
                        "name" => name = val,
                        "enabled" => enabled = is_true(&val),
                        "timer" => timer = val.parse().unwrap_or(0),
                        "comment" => comment = val,
                        "pinned" => pinned = is_true(&val),
                        "kind" => {
                            kind = match val.as_str() {
                                "service" => AppKind::Service,
                                "system" => AppKind::System,
                                "uwp" => AppKind::Uwp,
                                _ => AppKind::Regular,
                            }
                        }
                        _ => {}
                    }
                }
                if !path.is_empty() {
                    if name.is_empty() {
                        name = Path::new(&path)
                            .file_name()
                            .map(|s| s.to_string_lossy().into_owned())
                            .unwrap_or_else(|| path.clone());
                    }
                    apps.push(AppItem {
                        path,
                        display_name: name,
                        kind,
                        enabled,
                        timer_until: timer,
                        comment,
                        pinned,
                    });
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
        buf.clear();
    }
    apps
}

fn parse_settings(text: &str) -> Settings {
    let mut settings = Settings::default();
    let mut reader = Reader::from_str(text);
    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Empty(e)) if e.name().as_ref() == b"settings" => {
                for attr in e.attributes().flatten() {
                    let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                    let val = attr.unescape_value().map(|v| v.to_string()).unwrap_or_default();
                    match key.as_str() {
                        "allow_loopback" => settings.allow_loopback = is_true(&val),
                        "allow_ipv6" => settings.allow_ipv6 = is_true(&val),
                        "allow_lan" => settings.allow_lan = is_true(&val),
                        "user_allows_override_blocklist" => {
                            settings.user_allows_override_blocklist = is_true(&val)
                        }
                        "log_to_file" => settings.log_to_file = is_true(&val),
                        "filters_temporary" => settings.filters_temporary = is_true(&val),
                        _ => {}
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => break,
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
        "\t<settings allow_loopback=\"{}\" allow_ipv6=\"{}\" allow_lan=\"{}\" user_allows_override_blocklist=\"{}\" log_to_file=\"{}\" filters_temporary=\"{}\" />\n",
        bool_attr(s.allow_loopback),
        bool_attr(s.allow_ipv6),
        bool_attr(s.allow_lan),
        bool_attr(s.user_allows_override_blocklist),
        bool_attr(s.log_to_file),
        bool_attr(s.filters_temporary)
    ));
    xml.push_str("\t<apps>\n");
    for app in &profile.apps {
        xml.push_str(&format!(
            "\t\t<item path=\"{}\" name=\"{}\" enabled=\"{}\" timer=\"{}\" kind=\"{}\" pinned=\"{}\" comment=\"{}\" />\n",
            esc(&app.path),
            esc(&app.display_name),
            bool_attr(app.enabled),
            app.timer_until,
            kind_attr(app.kind),
            bool_attr(app.pinned),
            esc(&app.comment)
        ));
    }
    xml.push_str("\t</apps>\n\t<rules_user>\n");
    for rule in profile.rules.iter().filter(|r| r.origin == RuleOrigin::User) {
        xml.push_str(&rule_item(rule));
    }
    xml.push_str("\t</rules_user>\n\t<rules_config>\n");
    for rule in profile.rules.iter().filter(|r| r.origin != RuleOrigin::User) {
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
        let rules = parse_internal();
        assert!(rules.len() > 20);
        assert!(rules.iter().any(|r| r.name == "DNS"));
        let dns = rules.iter().find(|r| r.name == "DNS").unwrap();
        assert!(dns.enabled);
        assert_eq!(dns.protocol, 17);
    }
}
