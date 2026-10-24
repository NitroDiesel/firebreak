//! Turns the profile and the live tables into list lines for one tab.
//! Built only when something changes, never per frame.

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
            Tab::Apps => "Apps",
            Tab::Services => "Services",
            Tab::Uwp => "UWP apps",
            Tab::Blocklist => "Blocklist",
            Tab::System => "System rules",
            Tab::User => "User rules",
            Tab::Connections => "Connections",
            Tab::Packets => "Packets log",
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
        static CONNECTIONS: [Column; 5] = [
            col("Name", 0.0, false),
            col("Local address", 200.0, false),
            col("Remote address", 200.0, false),
            col("Protocol", 80.0, true),
            col("State", 110.0, true),
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
            "Apps with internet access",
            "Apps with timer",
            "Apps with user rules",
            "Apps without internet access",
        ];
        return grouped(apps(kind, src), &titles, |_| "", src);
    }
    if let Some(origin) = tab.rule_origin() {
        let titles = ["Enabled rules", "Enabled rules", "Disabled rules"];
        let suffix = |group: u8| match group {
            0 => " [for all]",
            1 => " [for apps]",
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
            title: format!("{title} ({count}/{total}){}", suffix(group)),
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
        let fill = if !exists {
            Some(theme::FILL_INVALID)
        } else if app.pinned {
            Some(theme::FILL_UNDELETE)
        } else if system {
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
            AppKind::Regular => Icon::File {
                path: app.path.clone(),
                generic: !exists,
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
        if !app.comment.is_empty() {
            hint.push('\n');
            hint.push_str(&app.comment);
        }
        if app.has_timer() {
            hint.push_str(&format!("\nTimer: until {}", shell::format_time(app.timer_until)));
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
        let fill = if rule.enabled && !valid {
            Some(theme::FILL_INVALID)
        } else if rule.for_apps() {
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
        apps.insert(0, "Services");
    }
    if rule.kernel {
        apps.insert(0, "System");
    }
    if !apps.is_empty() {
        lines.push(format!("Apps: {}", apps.join(", ")));
    }
    if !valid {
        lines.push("Syntax error in rule!".into());
    }
    lines.join("\n")
}

fn connections(src: &Source) -> Vec<Entry> {
    src.connections
        .iter()
        .enumerate()
        .filter(|(_, c)| query_matches(src.query, false, &[&c.name, &c.local, &c.remote, c.proto]))
        .map(|(id, c)| {
            let row = Row {
                id,
                cells: vec![
                    c.name.clone(),
                    c.local.clone(),
                    c.remote.clone(),
                    c.proto.to_string(),
                    c.state.clone(),
                ],
                check: None,
                icon: Icon::None,
                fill: None,
                hint: Some(format!("PID {}", c.pid)),
            };
            Entry {
                group: 0,
                key: text_key(&row, src.sort.column),
                row,
            }
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
