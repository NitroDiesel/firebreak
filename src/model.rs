//! Shared types. Names follow the C enums in `src/main.h`.

use std::time::{SystemTime, UNIX_EPOCH};

pub const APP_NAME: &str = "simplewall";
pub const APP_VERSION: &str = "3.9.1";

/// Same provider key as `GUID_WfpProvider` in `src/wfp.h`.
#[allow(dead_code)]
pub const PROVIDER_GUID: &str = "B0D553E2-C6A0-4A9A-AEB8-C752483ED62F";
/// Same sublayer key as `GUID_WfpSublayer`.
#[allow(dead_code)]
pub const SUBLAYER_GUID: &str = "9FEE6F59-B951-4F9A-B52F-133DCF7A4279";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppKind {
    Regular,
    Service,
    System,
    Uwp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Outbound = 0,
    Inbound = 1,
    Any = 2,
}

impl Direction {
    pub fn from_attr(value: i64) -> Self {
        match value {
            1 => Self::Inbound,
            2 => Self::Any,
            _ => Self::Outbound,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Outbound => "Outbound",
            Self::Inbound => "Inbound",
            Self::Any => "Any",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleAction {
    Permit,
    Block,
}

impl RuleAction {
    pub fn label(self) -> &'static str {
        match self {
            Self::Permit => "Allow",
            Self::Block => "Block",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleOrigin {
    System,
    Blocklist,
    Custom,
    User,
}

#[derive(Clone, Debug)]
pub struct AppItem {
    pub path: String,
    pub display_name: String,
    pub kind: AppKind,
    pub enabled: bool,
    /// Unix seconds. Zero means no timer.
    pub timer_until: u64,
    pub comment: String,
    pub pinned: bool,
}

impl AppItem {
    pub fn allowed_now(&self) -> bool {
        if !self.enabled {
            return false;
        }
        if self.timer_until == 0 {
            return true;
        }
        now_unix() < self.timer_until
    }
}

#[derive(Clone, Debug)]
pub struct Rule {
    pub name: String,
    pub remote: String,
    pub local: String,
    pub direction: Direction,
    pub action: RuleAction,
    pub protocol: u8,
    pub enabled: bool,
    pub origin: RuleOrigin,
    /// Service names or executable paths. Empty means every app.
    pub apps: Vec<String>,
    pub services: bool,
    pub kernel: bool,
    pub readonly: bool,
}

#[derive(Clone, Debug)]
pub struct Settings {
    pub allow_loopback: bool,
    pub allow_ipv6: bool,
    pub allow_lan: bool,
    /// User and custom allow rules outrank the internal blocklist.
    pub user_allows_override_blocklist: bool,
    pub log_to_file: bool,
    pub filters_temporary: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            allow_loopback: true,
            allow_ipv6: true,
            allow_lan: false,
            user_allows_override_blocklist: true,
            log_to_file: false,
            filters_temporary: false,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Profile {
    pub apps: Vec<AppItem>,
    pub rules: Vec<Rule>,
    pub settings: Settings,
}

pub fn query_matches(query: &str, regex: bool, fields: &[&str]) -> bool {
    let query = query.trim();
    if query.is_empty() {
        return true;
    }
    if regex || query.starts_with("re:") {
        let pattern = query.strip_prefix("re:").unwrap_or(query);
        return match regex::Regex::new(&format!("(?i){pattern}")) {
            Ok(re) => fields.iter().any(|field| re.is_match(field)),
            Err(_) => false,
        };
    }
    let needle = query.to_ascii_lowercase();
    fields.iter().any(|field| field.to_ascii_lowercase().contains(&needle))
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn substring_and_regex_search() {
        assert!(query_matches("wall", false, &["simplewall.exe"]));
        assert!(!query_matches("nope", false, &["simplewall.exe"]));
        assert!(query_matches(r"re:simple.*exe", false, &["simplewall.exe"]));
        assert!(!query_matches(r"re:[", false, &["simplewall.exe"]));
    }
}


