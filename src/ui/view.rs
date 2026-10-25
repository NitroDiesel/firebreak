//! Turns the profile and the live tables into list lines for one tab.
//! Built only when something changes, never per frame.

use crate::i18n::t;
use std::cmp::Ordering;
use std::collections::HashSet;

use crate::log::Endpoint;
use crate::model::{protocol_label, query_matches, AppItem, AppKind, Profile, Rule, RuleAction, RuleOrigin};
use crate::netevents::Packet;

use super::list::{Column, Icon, Line, Row, Sort};
use super::shell;
use super::theme;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Tab {
    Apps,
    Services,
    Uwp,
    Blocklist,
    System,
    User,
    Connections,
    Packets,
}

impl Tab {
    pub const ALL: [Tab; 8] = [
        Tab::Apps,
        Tab::Services,
        Tab::Uwp,
        Tab::Blocklist,
        Tab::System,
        Tab::User,
        Tab::Connections,
        Tab::Packets,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Tab::Apps => t("Apps"),
            Tab::Services => t("Services"),
            Tab::Uwp => t("UWP apps"),
            Tab::Blocklist => t("Blocklist"),
            Tab::System => t("System rules"),
            Tab::User => t("User rules"),
            Tab::Connections => t("Connections"),
            Tab::Packets => t("Packets log"),
        }
    }

    pub fn index(self) -> usize {
        Tab::ALL.iter().position(|t| *t == self).unwrap_or(0)
    }

    pub fn app_kind(self) -> Option<AppKind> {
        match self {
            Tab::Apps => Some(AppKind::Regular),
            Tab::Services => Some(AppKind::Service),
            Tab::Uwp => Some(AppKind::Uwp),
            _ => None,
        }
    }

    pub fn rule_origin(self) -> Option<RuleOrigin> {
        match self {
            Tab::Blocklist => Some(RuleOrigin::Blocklist),
            Tab::System => Some(RuleOrigin::System),
            Tab::User => Some(RuleOrigin::User),
            _ => None,
        }
    }

    /// Columns, with download, upload, and total on the Connections tab when
    /// traffic statistics are available.
    pub fn columns_for(self, traffic: bool) -> &'static [Column] {
        const fn col(title: &'static str, width: f32, right: bool) -> Column {
            Column { title, width, right }
        }
        static CONNECTIONS_TRAFFIC: [Column; 9] = [
            col("Name", 0.0, false),
            col("Local address", 160.0, false),
            col("Remote address", 160.0, false),
            col("Host", 150.0, false),
            col("Protocol", 60.0, true),
            col("State", 90.0, true),
            col("Download", 80.0, true),
            col("Upload", 80.0, true),
            col("Total", 80.0, true),
        ];
        if traffic && self == Tab::Connections {
            &CONNECTIONS_TRAFFIC
        } else {
            self.columns()
        }
    }

    pub fn columns(self) -> &'static [Column] {
        const fn col(title: &'static str, width: f32, right: bool) -> Column {
            Column { title, width, right }
        }
        static APPS: [Column; 2] = [col("Name", 0.0, false), col("Added", 170.0, true)];
        static RULES: [Column; 3] = [
            col("Name", 0.0, false),
            col("Protocol", 110.0, true),
            col("Direction", 110.0, true),
        ];
        static CONNECTIONS: [Column; 6] = [
            col("Name", 0.0, false),
            col("Local address", 190.0, false),
            col("Remote address", 190.0, false),
            col("Host", 200.0, false),
            col("Protocol", 70.0, true),
            col("State", 100.0, true),
        ];
        static PACKETS: [Column; 6] = [
            col("Name", 0.0, false),
            col("Date", 160.0, false),
            col("Local address", 180.0, false),
            col("Remote address", 180.0, false),
            col("Protocol", 80.0, true),
            col("Direction", 90.0, true),
        ];
        match self {
            Tab::Apps | Tab::Services | Tab::Uwp => &APPS,
            Tab::Blocklist | Tab::System | Tab::User => &RULES,
            Tab::Connections => &CONNECTIONS,
            Tab::Packets => &PACKETS,
        }
    }
}

pub fn app_on_tab(app: &AppItem, kind: AppKind) -> bool {
    match kind {
        AppKind::Regular => matches!(app.kind, AppKind::Regular | AppKind::System),
        other => app.kind == other,
    }
}

pub fn rule_on_tab(rule: &Rule, origin: RuleOrigin) -> bool {
    match origin {
        RuleOrigin::User => matches!(rule.origin, RuleOrigin::User | RuleOrigin::Custom),
        other => rule.origin == other,
    }
}

pub struct Source<'a> {
    pub profile: &'a Profile,
    pub connections: &'a [Endpoint],
    pub packets: &'a [Packet],
    pub query: &'a str,
    pub sort: Sort,
    pub collapsed: &'a HashSet<u8>,
    /// Lowercase path to signer (None = not signed), from the background checks.
    pub signers: &'a std::collections::HashMap<String, Option<String>>,
    /// Lowercase paths of apps with an established connection.
    pub connected: &'a HashSet<String>,
    /// Host names for remote addresses.
    pub hosts: &'a std::collections::HashMap<std::net::IpAddr, Option<String>>,
    /// Show the traffic columns on the Connections tab.
    pub traffic: bool,
}

enum Key {
    Text(String),
    Num(u64),
}

impl Key {
    fn cmp(&self, other: &Key) -> Ordering {
        match (self, other) {
            (Key::Num(a), Key::Num(b)) => a.cmp(b),
            (Key::Text(a), Key::Text(b)) => a.cmp(b),
            _ => Ordering::Equal,
        }
    }
}

struct Entry {
    group: u8,
    key: Key,
    row: Row,
}

pub fn build(tab: Tab, src: &Source) -> Vec<Line> {
    if let Some(kind) = tab.app_kind() {
        let titles = [
            t("Apps with internet access"),
            t("Apps with timer"),
            t("Apps with user rules"),
            t("Apps without internet access"),
        ];
        return grouped(apps(kind, src), &titles, |_| "", src);
    }
    if let Some(origin) = tab.rule_origin() {
        let titles = [t("Enabled rules"), t("Enabled rules"), t("Disabled rules")];
        let suffix = |group: u8| match group {
            0 => t("for all"),
            1 => t("for apps"),
            _ => "",
        };
        return grouped(rules(origin, src), &titles, suffix, src);
    }
    let mut entries = if tab == Tab::Connections {
        connections(src)
    } else {
        packets(src)
    };
    sort(&mut entries, src.sort);
    entries.into_iter().map(|e| Line::Row(e.row)).collect()
}

fn grouped(mut entries: Vec<Entry>, titles: &[&str], suffix: impl Fn(u8) -> &'static str, src: &Source) -> Vec<Line> {
    sort(&mut entries, src.sort);
    let total = entries.len();
    let mut lines = Vec::with_capacity(total + titles.len());
    for (group, title) in titles.iter().enumerate() {
        let group = group as u8;
        let count = entries.iter().filter(|e| e.group == group).count();
        if count == 0 {
            continue;
        }
        let collapsed = src.collapsed.contains(&group);
        lines.push(Line::Group {
            id: group,
            title: match suffix(group) {
                "" => format!("{title} ({count}/{total})"),
                tag => format!("{title} ({count}/{total}) [{tag}]"),
            },
            collapsed,
        });
        if !collapsed {
            lines.extend(
                entries
                    .iter_mut()
                    .filter(|e| e.group == group)
                    .map(|e| Line::Row(std::mem::replace(&mut e.row, placeholder()))),
            );
        }
    }
    lines
}

fn placeholder() -> Row {
    Row {
        id: 0,
        cells: Vec::new(),
        check: None,
        icon: Icon::None,
        fill: None,
        hint: None,
    }
}

fn sort(entries: &mut [Entry], sort: Sort) {
    entries.sort_by(|a, b| {
        let order = a.key.cmp(&b.key);
        if sort.descending {
            order.reverse()
        } else {
            order
        }
    });
}

fn text_key(row: &Row, column: usize) -> Key {
    Key::Text(row.cells.get(column).map(|c| c.to_lowercase()).unwrap_or_default())
}

fn apps(kind: AppKind, src: &Source) -> Vec<Entry> {
    let profile = src.profile;
    let windows = std::env::var("SystemRoot")
        .unwrap_or_else(|_| r"C:\Windows".into())
        .to_lowercase();
    let filenames_only = profile.settings.show_filenames_only;
    let mut out = Vec::new();
    for (id, app) in profile.apps.iter().enumerate() {
        if !app_on_tab(app, kind)
            || !query_matches(src.query, false, &[&app.display_name, &app.path, &app.comment])
        {
            continue;
        }
        let exists = app.kind != AppKind::Regular || std::path::Path::new(&app.path).exists();
        let has_rule = profile.app_has_rule(app);
        let system = match app.kind {
            AppKind::Regular => app.path.to_lowercase().starts_with(&windows),
            AppKind::System | AppKind::Service => true,
            AppKind::Uwp => false,
        };
        // Outer None: not checked (yet); inner None: not signed.
        let signer = (profile.settings.check_signatures && app.kind == AppKind::Regular)
            .then(|| src.signers.get(&app.path.to_lowercase()).cloned())
            .flatten();
        let connected = src.connected.contains(&app.path.to_lowercase());
        // Same order as `_app_getappcolor`: invalid, connection, signed, undeletable, system.
        let h = &profile.settings;
        let fill = if !h.highlighting {
            None
        } else if h.highlight_invalid && !exists {
            Some(theme::FILL_INVALID)
        } else if h.highlight_connection && connected {
            Some(theme::FILL_CONNECTION)
        } else if h.highlight_signed && matches!(signer, Some(Some(_))) {
            Some(theme::FILL_SIGNED)
        } else if h.highlight_undelete && app.pinned {
            Some(theme::FILL_UNDELETE)
        } else if h.highlight_system && system {
            Some(theme::FILL_SYSTEM)
        } else {
            None
        };
        let name = if app.kind == AppKind::Regular && !filenames_only {
            app.path.clone()
        } else {
            app.display_name.clone()
        };
        let icon = match app.kind {
            // A missing file shows the error icon too, not only the red fill.
            AppKind::Regular if !exists => Icon::Error,
            AppKind::Regular => Icon::File {
                path: app.path.clone(),
                generic: false,
            },
            AppKind::System => Icon::File {
                path: format!(r"{windows}\system32\ntoskrnl.exe"),
                generic: false,
            },
            AppKind::Service => Icon::File {
                path: format!(r"{windows}\system32\svchost.exe"),
                generic: false,
            },
            AppKind::Uwp => Icon::File {
                path: "app.exe".into(),
                generic: true,
            },
        };
        let mut hint = app.path.clone();
        // What the row's fill means, in words.
        for (on, state) in [
            (!exists, "File not found"),
            (connected, "Has an active connection"),
            (app.pinned, "Pinned"),
            (system && app.kind == AppKind::Regular, "System file"),
        ] {
            if on {
                hint.push('\n');
                hint.push_str(state);
            }
        }
        if !app.comment.is_empty() {
            hint.push('\n');
            hint.push_str(&app.comment);
        }
        if app.has_timer() {
            hint.push_str(&format!("\nTimer: until {}", shell::format_time(app.timer_until)));
        }
        match &signer {
            Some(Some(name)) if !name.is_empty() => hint.push_str(&format!("\nSignature: {name}")),
            Some(Some(_)) => hint.push_str("\nSignature: valid"),
            Some(None) => hint.push_str("\nSignature: not signed"),
            None => {}
        }
        let group = if app.enabled {
            if app.has_timer() {
                1
            } else {
                0
            }
        } else if has_rule {
            2
        } else {
            3
        };
        let row = Row {
            id,
            cells: vec![name, shell::format_time(app.added)],
            check: Some(app.enabled),
            icon,
            fill,
            hint: Some(hint),
        };
        let key = if src.sort.column == 1 {
            Key::Num(app.added)
        } else {
            text_key(&row, 0)
        };
        out.push(Entry { group, key, row });
    }
    out
}

fn rules(origin: RuleOrigin, src: &Source) -> Vec<Entry> {
    let mut out = Vec::new();
    for (id, rule) in src.profile.rules.iter().enumerate() {
        if !rule_on_tab(rule, origin)
            || !query_matches(src.query, false, &[&rule.name, &rule.remote, &rule.local])
        {
            continue;
        }
        let valid = rule.is_valid();
        let h = &src.profile.settings;
        let fill = if !h.highlighting {
            None
        } else if h.highlight_invalid && rule.enabled && !valid {
            Some(theme::FILL_INVALID)
        } else if h.highlight_special && rule.for_apps() {
            Some(theme::FILL_SPECIAL)
        } else {
            None
        };
        let icon = if !valid {
            Icon::Error
        } else if rule.action == RuleAction::Permit {
            Icon::Allow
        } else {
            Icon::Block
        };
        let group = match (rule.enabled, rule.for_apps()) {
            (true, false) => 0,
            (true, true) => 1,
            (false, _) => 2,
        };
        let row = Row {
            id,
            cells: vec![
                rule.name.clone(),
                protocol_label(rule.protocol).to_string(),
                rule.direction.label().to_string(),
            ],
            check: Some(rule.enabled),
            icon,
            fill,
            hint: Some(rule_hint(rule, valid)),
        };
        let key = text_key(&row, src.sort.column);
        out.push(Entry { group, key, row });
    }
    out
}

fn rule_hint(rule: &Rule, valid: bool) -> String {
    let mut lines = vec![format!("{} — {}", rule.action.label(), rule.direction.label())];
    if !rule.remote.is_empty() {
        lines.push(format!("Remote: {}", rule.remote));
    }
    if !rule.local.is_empty() {
        lines.push(format!("Local: {}", rule.local));
    }
    let mut apps: Vec<&str> = rule.apps.iter().map(String::as_str).collect();
    if rule.services {
        apps.insert(0, t("Services"));
    }
    if rule.kernel {
        apps.insert(0, "System");
    }
    if !apps.is_empty() {
        lines.push(format!("Apps: {}", apps.join(", ")));
    }
    if !valid {
        lines.push(t("Syntax error in rule!").into());
    }
    lines.join("\n")
}

fn connections(src: &Source) -> Vec<Entry> {
    src.connections
        .iter()
        .enumerate()
        .map(|(id, c)| {
            let host = c
                .remote_ip
                .and_then(|ip| src.hosts.get(&ip).cloned().flatten())
                .unwrap_or_default();
            (id, c, host)
        })
        .filter(|(_, c, host)| query_matches(src.query, false, &[&c.name, &c.path, &c.local, &c.remote, host, c.proto]))
        .map(|(id, c, host)| {
            let icon = if c.path.contains('\\') {
                Icon::File { path: c.path.clone(), generic: false }
            } else {
                Icon::None
            };
            let mut hint = format!("PID {}", c.pid);
            if !c.path.is_empty() {
                hint = format!("{}\n{hint}", c.path);
            }
            let mut cells = vec![
                c.name.clone(),
                c.local.clone(),
                c.remote.clone(),
                host,
                c.proto.to_string(),
                c.state.to_string(),
            ];
            let traffic = c.traffic.unwrap_or_default();
            if src.traffic {
                let known = c.traffic.is_some();
                let show = |text: String| if known { text } else { String::new() };
                cells.push(show(format!("{}/s", format_bytes(traffic.down_per_sec))));
                cells.push(show(format!("{}/s", format_bytes(traffic.up_per_sec))));
                cells.push(show(format_bytes(traffic.total)));
            }
            let row = Row {
                id,
                cells,
                check: None,
                icon,
                fill: None,
                hint: Some(hint),
            };
            // The traffic columns sort by number, not by their text.
            let key = match src.sort.column {
                6 if src.traffic => Key::Num(traffic.down_per_sec),
                7 if src.traffic => Key::Num(traffic.up_per_sec),
                8 if src.traffic => Key::Num(traffic.total),
                column => text_key(&row, column),
            };
            Entry { group: 0, key, row }
        })
        .collect()
}

fn packets(src: &Source) -> Vec<Entry> {
    src.packets
        .iter()
        .enumerate()
        .filter(|(_, p)| query_matches(src.query, false, &[&p.path, &p.local(), &p.remote()]))
        .map(|(id, p)| {
            let row = Row {
                id,
                cells: vec![
                    p.name().to_string(),
                    shell::format_time(p.time),
                    p.local(),
                    p.remote(),
                    protocol_label(p.protocol).to_string(),
                    p.direction().to_string(),
                ],
                check: None,
                icon: Icon::Block,
                fill: None,
                hint: None,
            };
            let key = if src.sort.column == 1 {
                Key::Num(p.time)
            } else {
                text_key(&row, src.sort.column)
            };
            Entry { group: 0, key, row }
        })
        .collect()
}

/// 1536 -> "1.5 KB", like `_r_format_bytesize64`.
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_read_like_the_original() {
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(5 * 1024 * 1024), "5.0 MB");
    }
}
