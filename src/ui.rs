//! Window: apps, rules, connections, and the filter buttons.

use eframe::egui;

use crate::apps;
use crate::log::{self, Endpoint};
use crate::model::{
    now_unix, query_matches, AppKind, Direction, Profile, Rule, RuleAction, RuleOrigin,
};
use crate::profile;
use crate::wfp;

pub struct SimplewallApp {
    profile: Profile,
    status: String,
    tab: Tab,
    filter: String,
    connections: Vec<Endpoint>,
    rule_name: String,
    rule_remote: String,
    rule_local: String,
    rule_protocol: String,
    rule_block: bool,
    rule_inbound: bool,
    regex_search: bool,
    selected_app: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Apps,
    Rules,
    Connections,
}

impl SimplewallApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let mut profile = profile::load();
        if profile.apps.is_empty() {
            profile.apps = apps::enumerate();
        }
        Self {
            profile,
            status: "Filters are off until you enable them.".into(),
            tab: Tab::Apps,
            filter: String::new(),
            connections: Vec::new(),
            rule_name: String::new(),
            rule_remote: String::new(),
            rule_local: String::new(),
            rule_protocol: "0".into(),
            rule_block: false,
            rule_inbound: false,
            regex_search: false,
            selected_app: None,
        }
    }

    fn save(&mut self) {
        match profile::save(&self.profile) {
            Ok(path) => self.status = format!("saved {}", path.display()),
            Err(err) => self.status = err,
        }
    }

    fn refresh_apps(&mut self) {
        let live = apps::enumerate();
        self.profile.apps = apps::merge(&self.profile.apps, live);
        self.status = format!("{} apps", self.profile.apps.len());
    }
}

impl eframe::App for SimplewallApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::TopBottomPanel::top("bar").show(ctx, |ui| {
            ui.horizontal_wrapped(|ui| {
                if ui.button("Enable filters").clicked() {
                    self.status = match wfp::install(&self.profile, false) {
                        Ok(msg) => msg,
                        Err(err) => err,
                    };
                    self.profile.settings.filters_temporary = false;
                    self.save();
                }
                if ui.button("Enable until reboot").clicked() {
                    self.status = match wfp::install(&self.profile, true) {
                        Ok(msg) => msg,
                        Err(err) => err,
                    };
                    self.profile.settings.filters_temporary = true;
                    self.save();
                }
                if ui.button("Disable filters").clicked() {
                    self.status = match wfp::uninstall() {
                        Ok(msg) => msg,
                        Err(err) => err,
                    };
                }
                if ui.button("Refresh apps").clicked() {
                    self.refresh_apps();
                }
                if ui.button("Save").clicked() {
                    self.save();
                }
            });
            ui.label(&self.status);
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.tab, Tab::Apps, "Apps");
                ui.selectable_value(&mut self.tab, Tab::Rules, "Rules");
                ui.selectable_value(&mut self.tab, Tab::Connections, "Connections");
            });
            ui.separator();
            match self.tab {
                Tab::Apps => self.apps_tab(ui),
                Tab::Rules => self.rules_tab(ui),
                Tab::Connections => self.conn_tab(ui),
            }
        });
    }
}

impl SimplewallApp {
    fn apps_tab(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            ui.label("Search");
            ui.text_edit_singleline(&mut self.filter);
            ui.checkbox(&mut self.regex_search, "Regex");
            ui.checkbox(&mut self.profile.settings.allow_loopback, "Allow loopback");
            ui.checkbox(&mut self.profile.settings.allow_ipv6, "Allow IPv6 bootstrap");
            ui.checkbox(&mut self.profile.settings.allow_lan, "Allow LAN");
            ui.checkbox(
                &mut self.profile.settings.user_allows_override_blocklist,
                "User allows beat blocklist",
            );
            ui.checkbox(&mut self.profile.settings.log_to_file, "Log installs to simplewall.csv");
        });
        ui.label("Checked apps are allowed. This program is always allowed. Pin keeps an app at the top. Prefix a search with re: or turn on Regex.");
        let query = self.filter.clone();
        let regex = self.regex_search;
        let mut order: Vec<usize> = (0..self.profile.apps.len()).collect();
        order.sort_by(|a, b| {
            let left = &self.profile.apps[*a];
            let right = &self.profile.apps[*b];
            right
                .pinned
                .cmp(&left.pinned)
                .then_with(|| left.display_name.to_lowercase().cmp(&right.display_name.to_lowercase()))
        });
        let mut select: Option<String> = None;
        let mut bad_regex = false;
        if regex || query.trim().starts_with("re:") {
            let pattern = query.trim().strip_prefix("re:").unwrap_or(query.trim());
            if !pattern.is_empty() && regex::Regex::new(&format!("(?i){pattern}")).is_err() {
                bad_regex = true;
            }
        }
        egui::ScrollArea::vertical().show(ui, |ui| {
            for index in order {
                let app = &mut self.profile.apps[index];
                if !query_matches(query.as_str(), regex, &[&app.display_name, &app.path, &app.comment]) {
                    continue;
                }
                let path = app.path.clone();
                ui.horizontal(|ui| {
                    if ui.small_button(if app.pinned { "unpin" } else { "pin" }).clicked() {
                        app.pinned = !app.pinned;
                    }
                    ui.checkbox(&mut app.enabled, "");
                    if ui.selectable_label(false, kind_label(app.kind)).clicked() {
                        select = Some(path.clone());
                    }
                    if ui.selectable_label(false, &app.display_name).clicked() {
                        select = Some(path);
                    }
                    if app.timer_until > now_unix() {
                        ui.label(format!("timer {}", app.timer_until));
                    }
                    ui.weak(&app.path);
                });
            }
        });
        if bad_regex {
            ui.colored_label(egui::Color32::LIGHT_RED, "Search is not a valid regular expression.");
        }
        if let Some(path) = select {
            self.selected_app = Some(path);
        }
        if let Some(path) = self.selected_app.clone() {
            if let Some(app) = self.profile.apps.iter_mut().find(|app| app.path == path) {
                ui.separator();
                ui.label(format!("Comment for {}", app.display_name));
                ui.text_edit_singleline(&mut app.comment);
            }
        }
    }

    fn rules_tab(&mut self, ui: &mut egui::Ui) {
        ui.collapsing("New rule", |ui| {
            ui.horizontal(|ui| {
                ui.label("Name");
                ui.text_edit_singleline(&mut self.rule_name);
            });
            ui.horizontal(|ui| {
                ui.label("Remote");
                ui.text_edit_singleline(&mut self.rule_remote);
            });
            ui.horizontal(|ui| {
                ui.label("Local");
                ui.text_edit_singleline(&mut self.rule_local);
            });
            ui.horizontal(|ui| {
                ui.label("Protocol (0 any, 6 TCP, 17 UDP)");
                ui.text_edit_singleline(&mut self.rule_protocol);
                ui.checkbox(&mut self.rule_block, "Block");
                ui.checkbox(&mut self.rule_inbound, "Inbound");
            });
            if ui.button("Add rule").clicked() && !self.rule_name.trim().is_empty() {
                let protocol = self.rule_protocol.parse().unwrap_or(0);
                self.profile.rules.push(Rule {
                    name: self.rule_name.trim().to_string(),
                    remote: self.rule_remote.trim().to_string(),
                    local: self.rule_local.trim().to_string(),
                    direction: if self.rule_inbound {
                        Direction::Inbound
                    } else {
                        Direction::Outbound
                    },
                    action: if self.rule_block {
                        RuleAction::Block
                    } else {
                        RuleAction::Permit
                    },
                    protocol,
                    enabled: true,
                    origin: RuleOrigin::User,
                    apps: Vec::new(),
                    services: false,
                    kernel: false,
                    readonly: false,
                });
                self.rule_name.clear();
                self.rule_remote.clear();
                self.rule_local.clear();
                self.save();
            }
        });
        ui.label("Rule text uses `;` between tokens: 80; 443; 192.168.0.0/16; [fe80::]:5355");
        let mut remove: Option<usize> = None;
        egui::ScrollArea::vertical().show(ui, |ui| {
            for (index, rule) in self.profile.rules.iter_mut().enumerate() {
                ui.horizontal(|ui| {
                    ui.checkbox(&mut rule.enabled, "");
                    ui.label(origin_label(rule.origin));
                    ui.label(rule.action.label());
                    ui.label(rule.direction.label());
                    if rule.protocol != 0 {
                        ui.label(format!("proto {}", rule.protocol));
                    }
                    ui.label(&rule.name);
                    if !rule.remote.is_empty() {
                        ui.weak(&rule.remote);
                    }
                    if !rule.local.is_empty() {
                        ui.weak(format!("local {}", rule.local));
                    }
                    if !rule.readonly && ui.small_button("delete").clicked() {
                        remove = Some(index);
                    }
                });
            }
        });
        if let Some(index) = remove {
            self.profile.rules.remove(index);
        }
    }

    fn conn_tab(&mut self, ui: &mut egui::Ui) {
        if ui.button("Refresh connections").clicked() {
            self.connections = log::connections();
            self.status = format!("{} endpoints", self.connections.len());
        }
        egui::ScrollArea::vertical().show(ui, |ui| {
            for row in &self.connections {
                ui.horizontal(|ui| {
                    ui.monospace(format!(
                        "{:<5} {:<12} pid {:<6} {} -> {}",
                        row.proto, row.state, row.pid, row.local, row.remote
                    ));
                });
            }
        });
    }
}

fn kind_label(kind: AppKind) -> &'static str {
    match kind {
        AppKind::Regular => "app",
        AppKind::Service => "svc",
        AppKind::System => "sys",
        AppKind::Uwp => "uwp",
    }
}

fn origin_label(origin: RuleOrigin) -> &'static str {
    match origin {
        RuleOrigin::System => "system",
        RuleOrigin::Blocklist => "blocklist",
        RuleOrigin::Custom => "custom",
        RuleOrigin::User => "user",
    }
}
