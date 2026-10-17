//! Main window laid out like the original simplewall dialog:
//! toolbar, tabs, a report list (name / protocol / direction), status bar.

use eframe::egui::{self, Color32, RichText, Stroke, TextStyle, Vec2};

use crate::apps;
use crate::log::{self, Endpoint};
use crate::model::{
    now_unix, query_matches, AppKind, Direction, Profile, Rule, RuleAction, RuleOrigin,
};
use crate::profile;
use crate::wfp;

const YELLOW: Color32 = Color32::from_rgb(255, 255, 196);
const ROW_LINE: Color32 = Color32::from_rgb(90, 90, 90);
const CHROME: Color32 = Color32::from_rgb(32, 32, 32);
const STATUS_BG: Color32 = Color32::from_rgb(12, 12, 12);

pub struct SimplewallApp {
    profile: Profile,
    status: String,
    filters_on: bool,
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
    show_settings: bool,
    show_editor: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Apps,
    Services,
    Uwp,
    Blocklist,
    System,
    User,
    Connections,
}

impl Tab {
    fn label(self) -> &'static str {
        match self {
            Self::Apps => "Apps",
            Self::Services => "Services",
            Self::Uwp => "UWP apps",
            Self::Blocklist => "Blocklist",
            Self::System => "System rules",
            Self::User => "User rules",
            Self::Connections => "Connections",
        }
    }

    fn all() -> &'static [Tab] {
        &[
            Self::Apps,
            Self::Services,
            Self::Uwp,
            Self::Blocklist,
            Self::System,
            Self::User,
            Self::Connections,
        ]
    }
}

impl SimplewallApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        apply_theme(&cc.egui_ctx);
        let mut profile = profile::load();
        if profile.apps.is_empty() {
            profile.apps = apps::enumerate();
        }
        let filters_on = wfp::filters_installed().unwrap_or(false);
        Self {
            profile,
            status: if filters_on {
                "Filtering is enabled.".into()
            } else {
                "Filtering is disabled.".into()
            },
            filters_on,
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
            show_settings: false,
            show_editor: false,
        }
    }

    fn save(&mut self) {
        match profile::save(&self.profile) {
            Ok(path) => self.status = format!("Saved {}", path.display()),
            Err(err) => self.status = err,
        }
    }

    fn refresh_apps(&mut self) {
        let live = apps::enumerate();
        self.profile.apps = apps::merge(&self.profile.apps, live);
        self.status = format!("{} apps", self.profile.apps.len());
    }

    fn set_filters(&mut self, enable: bool, temporary: bool) {
        self.status = if enable {
            match wfp::install(&self.profile, temporary) {
                Ok(msg) => {
                    self.filters_on = true;
                    self.profile.settings.filters_temporary = temporary;
                    self.save();
                    msg
                }
                Err(err) => err,
            }
        } else {
            match wfp::uninstall() {
                Ok(msg) => {
                    self.filters_on = false;
                    msg
                }
                Err(err) => err,
            }
        };
    }
}

impl eframe::App for SimplewallApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if ctx.input(|i| i.key_pressed(egui::Key::F) && i.modifiers.command) {
            ctx.memory_mut(|m| m.request_focus(egui::Id::new("find")));
        }

        egui::TopBottomPanel::top("toolbar")
            .frame(egui::Frame::NONE.fill(CHROME).inner_margin(6))
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    let filter_label = if self.filters_on {
                        "Disable filtering"
                    } else {
                        "Enable filtering"
                    };
                    let button = egui::Button::new(RichText::new(filter_label).strong());
                    if ui.add(button).clicked() {
                        let temporary = self.profile.settings.filters_temporary;
                        self.set_filters(!self.filters_on, temporary && !self.filters_on);
                    }
                    if ui.button("Until reboot").clicked() {
                        self.set_filters(true, true);
                    }
                    if ui.button("+").on_hover_text("Add a user rule").clicked() {
                        self.tab = Tab::User;
                        self.show_editor = true;
                    }
                    if ui.button("Refresh").clicked() {
                        self.refresh_apps();
                        if self.tab == Tab::Connections {
                            self.connections = log::connections();
                        }
                    }
                    if ui.button("Settings").clicked() {
                        self.show_settings = true;
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.checkbox(&mut self.regex_search, "Regex");
                        let edit = egui::TextEdit::singleline(&mut self.filter)
                            .id(egui::Id::new("find"))
                            .hint_text("Find... (Ctrl+F)")
                            .desired_width(220.0);
                        ui.add(edit);
                    });
                });
            });

        egui::TopBottomPanel::bottom("status")
            .frame(egui::Frame::NONE.fill(STATUS_BG).inner_margin(egui::Margin::symmetric(8, 4)))
            .show(ctx, |ui| {
                ui.label(RichText::new(&self.status).color(Color32::WHITE).size(12.0));
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.horizontal(|ui| {
                for tab in Tab::all() {
                    let selected = self.tab == *tab;
                    if ui.selectable_label(selected, tab.label()).clicked() {
                        self.tab = *tab;
                    }
                }
            });
            ui.separator();
            match self.tab {
                Tab::Apps => self.apps_page(ui, AppKind::Regular),
                Tab::Services => self.apps_page(ui, AppKind::Service),
                Tab::Uwp => self.apps_page(ui, AppKind::Uwp),
                Tab::Blocklist => self.rules_page(ui, RuleOrigin::Blocklist),
                Tab::System => self.rules_page(ui, RuleOrigin::System),
                Tab::User => self.rules_page(ui, RuleOrigin::User),
                Tab::Connections => self.conn_tab(ui),
            }
        });

        self.settings_window(ctx);
        self.editor_window(ctx);
    }
}

impl SimplewallApp {
    fn apps_page(&mut self, ui: &mut egui::Ui, kind: AppKind) {
        let query = self.filter.clone();
        let regex = self.regex_search;
        let bad_regex = search_is_bad(&query, regex);
        let mut order: Vec<usize> = (0..self.profile.apps.len())
            .filter(|index| app_on_tab(&self.profile.apps[*index], kind))
            .collect();
        order.sort_by(|a, b| {
            let left = &self.profile.apps[*a];
            let right = &self.profile.apps[*b];
            right.pinned.cmp(&left.pinned).then_with(|| {
                left.display_name
                    .to_lowercase()
                    .cmp(&right.display_name.to_lowercase())
            })
        });
        order.retain(|index| {
            let app = &self.profile.apps[*index];
            query_matches(query.as_str(), regex, &[&app.display_name, &app.path, &app.comment])
        });

        column_head(ui, &[("Name", 420.0), ("", 80.0)]);
        let mut select: Option<String> = None;
        egui::ScrollArea::vertical().show(ui, |ui| {
            for index in order {
                let app = &mut self.profile.apps[index];
                let path = app.path.clone();
                let row = ui.horizontal(|ui| {
                    ui.checkbox(&mut app.enabled, "");
                    let name = if app.pinned {
                        format!("{}  (pinned)", app.display_name)
                    } else {
                        app.display_name.clone()
                    };
                    if ui
                        .add_sized([420.0, 18.0], egui::Button::new(name).frame(false))
                        .clicked()
                    {
                        select = Some(path);
                    }
                    if app.timer_until > now_unix() {
                        ui.label(format!("until {}", app.timer_until));
                    }
                });
                paint_row_line(ui, row.response.rect);
            }
        });
        if bad_regex {
            ui.colored_label(Color32::LIGHT_RED, "Search is not a valid regular expression.");
        }
        if let Some(path) = select {
            self.selected_app = Some(path);
        }
        if let Some(path) = self.selected_app.clone() {
            if let Some(app) = self.profile.apps.iter_mut().find(|app| app.path == path) {
                if app_on_tab(app, kind) {
                    ui.separator();
                    ui.label(app.path.as_str());
                    ui.horizontal(|ui| {
                        ui.label("Comment");
                        ui.text_edit_singleline(&mut app.comment);
                        if ui.button(if app.pinned { "Unpin" } else { "Pin" }).clicked() {
                            app.pinned = !app.pinned;
                        }
                    });
                }
            }
        }
    }

    fn rules_page(&mut self, ui: &mut egui::Ui, origin: RuleOrigin) {
        let query = self.filter.clone();
        let regex = self.regex_search;
        if search_is_bad(&query, regex) {
            ui.colored_label(Color32::LIGHT_RED, "Search is not a valid regular expression.");
        }
        let indexes: Vec<usize> = self
            .profile
            .rules
            .iter()
            .enumerate()
            .filter(|(_, rule)| rule_on_tab(rule, origin))
            .filter(|(_, rule)| {
                query_matches(query.as_str(), regex, &[&rule.name, &rule.remote, &rule.local])
            })
            .map(|(index, _)| index)
            .collect();
        let enabled: Vec<usize> = indexes
            .iter()
            .copied()
            .filter(|index| self.profile.rules[*index].enabled)
            .collect();
        let disabled: Vec<usize> = indexes
            .iter()
            .copied()
            .filter(|index| !self.profile.rules[*index].enabled)
            .collect();

        column_head(ui, &[("Name", 460.0), ("Protocol", 90.0), ("Direction", 90.0)]);
        egui::ScrollArea::vertical().show(ui, |ui| {
            group_label(
                ui,
                &format!("Enabled rules ({}/{})", enabled.len(), indexes.len()),
            );
            let mut remove: Option<usize> = None;
            for index in enabled {
                if self.rule_row(ui, index) {
                    remove = Some(index);
                }
            }
            ui.add_space(8.0);
            group_label(ui, &format!("Disabled rules ({})", disabled.len()));
            for index in disabled {
                if self.rule_row(ui, index) {
                    remove = Some(index);
                }
            }
            if let Some(index) = remove {
                self.profile.rules.remove(index);
            }
        });
    }

    fn rule_row(&mut self, ui: &mut egui::Ui, index: usize) -> bool {
        let yellow = matches!(
            self.profile.rules[index].origin,
            RuleOrigin::System | RuleOrigin::Blocklist
        );
        let mut remove = false;
        let frame = egui::Frame::NONE
            .fill(if yellow { YELLOW } else { Color32::from_rgb(45, 45, 45) })
            .inner_margin(egui::Margin::symmetric(4, 1));
        frame.show(ui, |ui| {
            ui.horizontal(|ui| {
                let rule = &mut self.profile.rules[index];
                let text = if yellow { Color32::BLACK } else { Color32::WHITE };
                let title = match rule.action {
                    RuleAction::Block => format!("{} ({})", rule.name, rule.action.label()),
                    RuleAction::Permit => rule.name.clone(),
                };
                ui.checkbox(&mut rule.enabled, "");
                ui.add_sized(
                    [440.0, 16.0],
                    egui::Label::new(RichText::new(title).color(text)),
                );
                ui.add_sized(
                    [90.0, 16.0],
                    egui::Label::new(RichText::new(protocol_label(rule.protocol)).color(text)),
                );
                ui.add_sized(
                    [90.0, 16.0],
                    egui::Label::new(RichText::new(rule.direction.label()).color(text)),
                );
                if !rule.readonly && ui.small_button("delete").clicked() {
                    remove = true;
                }
            });
        });
        remove
    }

    fn conn_tab(&mut self, ui: &mut egui::Ui) {
        if self.connections.is_empty() {
            self.connections = log::connections();
        }
        column_head(
            ui,
            &[
                ("Protocol", 70.0),
                ("State", 110.0),
                ("PID", 70.0),
                ("Local", 220.0),
                ("Remote", 220.0),
            ],
        );
        egui::ScrollArea::vertical().show(ui, |ui| {
            for row in &self.connections {
                let line = ui.horizontal(|ui| {
                    cell(ui, &row.proto, 70.0);
                    cell(ui, &row.state, 110.0);
                    cell(ui, &row.pid.to_string(), 70.0);
                    cell(ui, &row.local, 220.0);
                    cell(ui, &row.remote, 220.0);
                });
                paint_row_line(ui, line.response.rect);
            }
        });
    }

    fn settings_window(&mut self, ctx: &egui::Context) {
        if !self.show_settings {
            return;
        }
        let mut open = true;
        egui::Window::new("Settings")
            .open(&mut open)
            .resizable(false)
            .show(ctx, |ui| {
                ui.checkbox(&mut self.profile.settings.allow_loopback, "Allow loopback");
                ui.checkbox(&mut self.profile.settings.allow_ipv6, "Allow IPv6 bootstrap");
                ui.checkbox(&mut self.profile.settings.allow_lan, "Allow LAN");
                ui.checkbox(
                    &mut self.profile.settings.user_allows_override_blocklist,
                    "User allows beat blocklist",
                );
                ui.checkbox(
                    &mut self.profile.settings.log_to_file,
                    "Log installs to simplewall.csv",
                );
                if ui.button("Save").clicked() {
                    self.save();
                }
            });
        self.show_settings = open;
    }

    fn editor_window(&mut self, ctx: &egui::Context) {
        if !self.show_editor {
            return;
        }
        let mut open = true;
        egui::Window::new("Add rule")
            .open(&mut open)
            .resizable(false)
            .show(ctx, |ui| {
                ui.label("Rule text uses `;` between tokens: 80; 443; 192.168.0.0/16");
                labeled(ui, "Name", &mut self.rule_name);
                labeled(ui, "Remote", &mut self.rule_remote);
                labeled(ui, "Local", &mut self.rule_local);
                ui.horizontal(|ui| {
                    ui.label("Protocol (0 any, 6 TCP, 17 UDP)");
                    ui.text_edit_singleline(&mut self.rule_protocol);
                });
                ui.checkbox(&mut self.rule_block, "Block");
                ui.checkbox(&mut self.rule_inbound, "Inbound");
                if ui.button("Add").clicked() && !self.rule_name.trim().is_empty() {
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
                    self.show_editor = false;
                }
            });
        self.show_editor = open && self.show_editor;
    }
}

fn apply_theme(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::dark();
    visuals.window_fill = CHROME;
    visuals.panel_fill = CHROME;
    visuals.extreme_bg_color = Color32::from_rgb(24, 24, 24);
    visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0_f32, ROW_LINE);
    ctx.set_visuals(visuals);
    let mut style = (*ctx.style()).clone();
    style.text_styles.insert(TextStyle::Body, egui::FontId::proportional(13.0));
    style.spacing.item_spacing = Vec2::new(8.0, 2.0);
    ctx.set_style(style);
}

fn app_on_tab(app: &crate::model::AppItem, kind: AppKind) -> bool {
    match kind {
        AppKind::Regular => matches!(app.kind, AppKind::Regular | AppKind::System),
        other => app.kind == other,
    }
}

fn rule_on_tab(rule: &Rule, origin: RuleOrigin) -> bool {
    match origin {
        RuleOrigin::User => matches!(rule.origin, RuleOrigin::User | RuleOrigin::Custom),
        other => rule.origin == other,
    }
}

fn protocol_label(protocol: u8) -> &'static str {
    match protocol {
        0 => "Any",
        1 => "icmp",
        6 => "tcp",
        17 => "udp",
        47 => "gre",
        58 => "icmpv6",
        _ => "other",
    }
}

fn search_is_bad(query: &str, regex: bool) -> bool {
    if !(regex || query.trim().starts_with("re:")) {
        return false;
    }
    let pattern = query.trim().strip_prefix("re:").unwrap_or(query.trim());
    !pattern.is_empty() && regex::Regex::new(&format!("(?i){pattern}")).is_err()
}

fn column_head(ui: &mut egui::Ui, columns: &[(&str, f32)]) {
    ui.horizontal(|ui| {
        for (label, width) in columns {
            ui.add_sized(
                [*width, 16.0],
                egui::Label::new(RichText::new(*label).strong().size(12.0)),
            );
        }
    });
    ui.separator();
}

fn group_label(ui: &mut egui::Ui, text: &str) {
    ui.label(RichText::new(text).strong().color(Color32::from_rgb(180, 180, 180)));
}

fn cell(ui: &mut egui::Ui, text: &str, width: f32) {
    ui.add_sized([width, 16.0], egui::Label::new(text));
}

fn labeled(ui: &mut egui::Ui, label: &str, value: &mut String) {
    ui.horizontal(|ui| {
        ui.add_sized([70.0, 18.0], egui::Label::new(label));
        ui.text_edit_singleline(value);
    });
}

fn paint_row_line(ui: &egui::Ui, rect: egui::Rect) {
    ui.painter().hline(
        rect.x_range(),
        rect.bottom(),
        Stroke::new(1.0_f32, Color32::from_rgb(55, 55, 55)),
    );
}
