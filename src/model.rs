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
            Self::Outbound => crate::i18n::t("Outbound"),
            Self::Inbound => crate::i18n::t("Inbound"),
            Self::Any => crate::i18n::t("Both"),
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
            Self::Permit => crate::i18n::t("Allow"),
            Self::Block => crate::i18n::t("Block"),
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
            Self::Spy => crate::i18n::t("Microsoft spying and telemetry"),
            Self::Update => crate::i18n::t("Microsoft update"),
            Self::Extra => crate::i18n::t("Microsoft applications"),
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
            Self::Disable => crate::i18n::t("Disable"),
            Self::Allow => crate::i18n::t("Allow"),
            Self::Block => crate::i18n::t("Block"),
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
    /// `is_silent`: never show a notification for this app.
    pub silent: bool,
    /// Unix seconds of the last notification, so one app does not alert every packet.
    pub last_notify: u64,
    /// SHA-256 of the file when it was allowed, with IsHashesEnabled.
    pub hash: String,
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
            silent: false,
            last_notify: 0,
            hash: String::new(),
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

/// A setting stored as one attribute of `<settings>` in profile.xml.
pub trait SettingValue: Sized {
    fn parse(text: &str) -> Option<Self>;
    fn format(&self) -> String;
}

impl SettingValue for bool {
    fn parse(text: &str) -> Option<Self> {
        Some(matches!(text.trim().to_ascii_lowercase().as_str(), "true" | "1" | "yes"))
    }
    fn format(&self) -> String {
        if *self { "true" } else { "false" }.into()
    }
}

impl SettingValue for u64 {
    fn parse(text: &str) -> Option<Self> {
        text.trim().parse().ok()
    }
    fn format(&self) -> String {
        self.to_string()
    }
}

impl SettingValue for String {
    fn parse(text: &str) -> Option<Self> {
        Some(text.to_string())
    }
    fn format(&self) -> String {
        self.clone()
    }
}

impl SettingValue for BlocklistState {
    fn parse(text: &str) -> Option<Self> {
        Self::from_attr(text)
    }
    fn format(&self) -> String {
        (*self as u8).to_string()
    }
}

/// Declares every setting once: field, type, default. Attribute names in
/// profile.xml are the field names. The C build's config key is noted beside each.
macro_rules! settings {
    ($( $(#[$doc:meta])* $field:ident : $ty:ty = $default:expr ),* $(,)?) => {
        #[derive(Clone, Debug, PartialEq)]
        pub struct Settings {
            $( $(#[$doc])* pub $field: $ty, )*
        }

        impl Default for Settings {
            fn default() -> Self {
                Self { $( $field: $default, )* }
            }
        }

        impl Settings {
            /// Every setting as (attribute, value), in declaration order.
            pub fn attrs(&self) -> Vec<(&'static str, String)> {
                vec![ $( (stringify!($field), SettingValue::format(&self.$field)), )* ]
            }

            /// Apply one attribute from profile.xml. Unknown keys and bad values are ignored.
            pub fn set_attr(&mut self, key: &str, value: &str) {
                match key {
                    $( stringify!($field) => {
                        if let Some(v) = <$ty as SettingValue>::parse(value) {
                            self.$field = v;
                        }
                    } )*
                    _ => {}
                }
            }
        }
    };
}

settings! {
    /// AllowLoopbackConnections
    allow_loopback: bool = true,
    /// AllowIPv6: neighbor discovery and 6to4.
    allow_ipv6: bool = true,
    /// Private, link-local, and multicast ranges.
    allow_lan: bool = false,
    /// User and custom allow rules outrank the internal blocklist.
    user_allows_override_blocklist: bool = true,
    filters_temporary: bool = false,
    /// BlockOutboundConnections: apps need permission to connect out.
    block_outbound: bool = true,
    /// BlockInboundConnections: apps need permission to accept connections.
    block_inbound: bool = true,
    /// UseStealthMode: no replies to port scans; also blocks inbound.
    stealth_mode: bool = true,
    /// InstallBoottimeFilters: filtering from boot, before the engine loads.
    boot_time_filters: bool = true,
    /// AllowIpForwarding: leave forwarded traffic alone in the boot-time filters
    /// (Mobile Hotspot, Internet Connection Sharing, NAT for VMs).
    allow_ip_forwarding: bool = false,
    /// IsWUFixEnabled: run the Windows Update services from their own svchost copy (wusvc.exe).
    wu_fix: bool = false,
    /// IsInternalRulesDisabled: install only the user's own rules.
    internal_rules_disabled: bool = false,
    // Same defaults as BlocklistSpyState / UpdateState / ExtraState in db.c.
    blocklist_spy: BlocklistState = BlocklistState::Block,
    blocklist_update: BlocklistState = BlocklistState::Disable,
    blocklist_extra: BlocklistState = BlocklistState::Disable,
    /// IsLogEnabled: write dropped packets to simplewall.csv.
    log_to_file: bool = false,
    /// IsLogUiEnabled: collect dropped packets for the Packets log tab.
    log_ui: bool = true,
    /// LogSizeLimitKb: the log file starts over once it reaches this size. 0 = no limit.
    log_size_limit_kb: u64 = 1024,
    /// IsExcludeStealth: leave stealth-mode and boot-time drops (port scans) out of the logs.
    log_exclude_stealth: bool = true,
    /// IsTrayIconSingleClick: one click on the tray icon shows or hides the window.
    tray_single_click: bool = true,
    /// IsNotificationsEnabled
    notifications: bool = true,
    /// IsNotificationsSound
    notifications_sound: bool = true,
    /// IsNotificationsFullscreenSilentMode: no sound while a full-screen app is in front.
    notifications_fullscreen_silent: bool = true,
    /// NotificationsTimeout: seconds before the same app can alert again.
    notifications_timeout: u64 = 60,
    /// IsCertificatesEnabled: check digital signatures and show signed apps in green.
    check_signatures: bool = true,
    /// IsOCSPEnabled: also check certificate revocation online.
    check_revocation: bool = false,
    /// IsHashesEnabled: block an allowed app when its file changes on disk.
    check_hashes: bool = false,
    /// IsNetworkMonitorEnabled: refresh the Connections tab every 2 seconds.
    network_monitor: bool = true,
    /// IsNetworkShowWaitConnections: list connections of processes that have exited.
    show_wait_connections: bool = true,
    /// IsUdpTrafficEnabled: count UDP bytes too, through a kernel network trace.
    udp_traffic: bool = false,
    /// IsNetworkResolutionsEnabled: look up host names for remote addresses.
    resolve_hostnames: bool = true,
    /// Check GitHub for a newer release once a day.
    check_updates: bool = true,
    /// Unix seconds of the last update check.
    last_update_check: u64 = 0,
    /// IsEnableAppMonitor: add programs to the list as they start.
    app_monitor: bool = false,
    /// ProfileType: 0 plain XML, 1 compressed, 2 encrypted.
    profile_type: u64 = 0,
    /// IsStartMinimized: start in the tray.
    start_minimized: bool = false,
    /// ConfirmExit2: ask before exiting while filters are on.
    confirm_exit: bool = true,
    always_on_top: bool = false,
    /// ShowFilenames
    show_filenames_only: bool = true,
    /// A section name in simplewall.lng; empty means English.
    language: String = String::new(),
    /// 0 follows Windows, 1 dark, 2 light.
    theme: u64 = 0,
    /// IsEnableHighlighting: color list rows at all.
    highlighting: bool = true,
    /// IsHighlightInvalid: missing files and rules with errors.
    highlight_invalid: bool = true,
    /// IsHighlightSpecial: rules for specific apps.
    highlight_special: bool = true,
    /// IsHighlightSigned
    highlight_signed: bool = true,
    /// IsHighlightConnection: apps with an active connection.
    highlight_connection: bool = true,
    /// IsHighlightSystem: apps in the Windows folder, services, and System.
    highlight_system: bool = true,
    /// IsHighlightUndelete: pinned apps.
    highlight_undelete: bool = true,
    /// CurrentTab
    current_tab: u64 = 0,
    /// Sort column and direction per tab ("column:desc,..."), like SortColumn / SortIsDescending.
    sorts: String = String::new(),
    /// Window size in points; 0 means the default.
    window_width: u64 = 0,
    window_height: u64 = 0,
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
        0 => crate::i18n::t("Any"),
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
    fn settings_round_trip_through_attributes() {
        let mut saved = Settings::default();
        saved.notifications = false;
        saved.notifications_timeout = 5;
        saved.blocklist_update = BlocklistState::Allow;
        let mut loaded = Settings::default();
        for (key, value) in saved.attrs() {
            loaded.set_attr(key, &value);
        }
        assert_eq!(saved, loaded);
        loaded.set_attr("notifications_timeout", "not a number");
        assert_eq!(loaded.notifications_timeout, 5);
    }

    #[test]
    fn blocklist_groups_follow_name_prefix() {
        assert_eq!(BlocklistGroup::of("spy_1.2.3.4"), Some(BlocklistGroup::Spy));
        assert_eq!(BlocklistGroup::of("extra_x"), Some(BlocklistGroup::Extra));
        assert_eq!(BlocklistGroup::of("other"), None);
    }
}
