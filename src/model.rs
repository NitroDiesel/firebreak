//! Shared types. Names follow the C enums in `src/main.h`.

use std::time::{SystemTime, UNIX_EPOCH};

pub const APP_NAME: &str = "simplewall";
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
/// `PROC_SYSTEM_NAME`. WFP reports kernel traffic under this app id, not a file path.
pub const SYSTEM_APP: &str = "System";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppKind {
    Regular,
    /// `path` is the service name. Filters match the service SID.
    Service,
    System,
    /// `path` is the package SID (`S-1-15-2-...`).
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
            Self::Any => "Both",
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

/// Blocklist rules are grouped by name prefix (`spy_`, `update_`, `extra_`),
/// and each group has one Disable / Allow / Block state, as in the C build.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlocklistGroup {
    Spy,
    Update,
    Extra,
}

impl BlocklistGroup {
    pub fn of(name: &str) -> Option<Self> {
        let lower = name.to_ascii_lowercase();
        if lower.starts_with("spy_") {
            Some(Self::Spy)
        } else if lower.starts_with("update_") {
            Some(Self::Update)
        } else if lower.starts_with("extra_") {
            Some(Self::Extra)
        } else {
            None
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Spy => "Microsoft spying and telemetry",
            Self::Update => "Microsoft update",
            Self::Extra => "Microsoft applications",
        }
    }

    pub fn all() -> [Self; 3] {
        [Self::Spy, Self::Update, Self::Extra]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlocklistState {
    Disable = 0,
    Allow = 1,
    Block = 2,
}

impl BlocklistState {
    pub fn from_attr(value: &str) -> Option<Self> {
        match value.trim() {
            "0" => Some(Self::Disable),
            "1" => Some(Self::Allow),
            "2" => Some(Self::Block),
            _ => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Disable => "Disable",
            Self::Allow => "Allow",
            Self::Block => "Block",
        }
    }

    pub fn all() -> [Self; 3] {
        [Self::Disable, Self::Allow, Self::Block]
    }
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
    /// Unix seconds when the app first appeared in the list.
    pub added: u64,
}

impl AppItem {
    pub fn new(path: String, display_name: String, kind: AppKind) -> Self {
        Self {
            path,
            display_name,
            kind,
            enabled: false,
            timer_until: 0,
            comment: String::new(),
            pinned: false,
            added: now_unix(),
        }
    }

    pub fn allowed_now(&self) -> bool {
        self.enabled && (self.timer_until == 0 || now_unix() < self.timer_until)
    }

    pub fn has_timer(&self) -> bool {
        self.timer_until != 0
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

impl Rule {
    /// The C build files these under "Enabled rules [for apps]".
    pub fn for_apps(&self) -> bool {
        self.services || self.kernel || !self.apps.is_empty()
    }

    /// False when the address text does not parse. Such a rule installs no filters.
    pub fn is_valid(&self) -> bool {
        crate::rules::parse_rule_list(&self.remote).is_ok()
            && crate::rules::parse_rule_list(&self.local).is_ok()
    }
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
    pub blocklist_spy: BlocklistState,
    pub blocklist_update: BlocklistState,
    pub blocklist_extra: BlocklistState,
    pub always_on_top: bool,
    pub show_filenames_only: bool,
    /// Keep dropped-packet events in the engine for the Packets log tab.
    pub log_ui: bool,
}

impl Settings {
    pub fn blocklist(&self, group: BlocklistGroup) -> BlocklistState {
        match group {
            BlocklistGroup::Spy => self.blocklist_spy,
            BlocklistGroup::Update => self.blocklist_update,
            BlocklistGroup::Extra => self.blocklist_extra,
        }
    }

    pub fn set_blocklist(&mut self, group: BlocklistGroup, state: BlocklistState) {
        match group {
            BlocklistGroup::Spy => self.blocklist_spy = state,
            BlocklistGroup::Update => self.blocklist_update = state,
            BlocklistGroup::Extra => self.blocklist_extra = state,
        }
    }
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
            // Same defaults as BlocklistSpyState / UpdateState / ExtraState in db.c.
            blocklist_spy: BlocklistState::Block,
            blocklist_update: BlocklistState::Disable,
            blocklist_extra: BlocklistState::Disable,
            always_on_top: false,
            show_filenames_only: true,
            log_ui: true,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Profile {
    pub apps: Vec<AppItem>,
    pub rules: Vec<Rule>,
    pub settings: Settings,
}

impl Profile {
    /// Apply one blocklist group state to its rules, like `_app_ruleblocklistsetchange`.
    pub fn apply_blocklist(&mut self, group: BlocklistGroup) {
        let state = self.settings.blocklist(group);
        for rule in &mut self.rules {
            if rule.origin == RuleOrigin::Blocklist && BlocklistGroup::of(&rule.name) == Some(group) {
                rule.enabled = state != BlocklistState::Disable;
                rule.action = if state == BlocklistState::Allow {
                    RuleAction::Permit
                } else {
                    RuleAction::Block
                };
            }
        }
    }

    /// True when a user rule names this app.
    pub fn app_has_rule(&self, app: &AppItem) -> bool {
        self.rules.iter().any(|rule| {
            rule.origin == RuleOrigin::User
                && rule.apps.iter().any(|path| path.eq_ignore_ascii_case(&app.path))
        })
    }

    /// `_app_isappunused`: a regular app that is gone from disk, or is not
    /// enabled, pinned, or named by a rule. Services and UWP packages come from
    /// the system inventory and are never purged.
    pub fn app_is_unused(&self, app: &AppItem) -> bool {
        if app.kind != AppKind::Regular {
            return false;
        }
        let used = app.enabled || app.pinned || self.app_has_rule(app);
        !used || !std::path::Path::new(&app.path).exists()
    }
}

pub fn protocol_label(protocol: u8) -> &'static str {
    match protocol {
        0 => "Any",
        1 => "icmp",
        2 => "igmp",
        6 => "tcp",
        17 => "udp",
        41 => "ipv6",
        47 => "gre",
        50 => "esp",
        51 => "ah",
        58 => "icmpv6",
        _ => "other",
    }
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
    let needle = query.to_lowercase();
    fields.iter().any(|field| field.to_lowercase().contains(&needle))
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

    #[test]
    fn blocklist_groups_follow_name_prefix() {
        assert_eq!(BlocklistGroup::of("spy_1.2.3.4"), Some(BlocklistGroup::Spy));
        assert_eq!(BlocklistGroup::of("extra_x"), Some(BlocklistGroup::Extra));
        assert_eq!(BlocklistGroup::of("other"), None);
    }
}
