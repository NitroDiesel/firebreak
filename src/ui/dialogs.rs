//! Rule editor, app properties, settings, about, and the filtering confirmation.

use eframe::egui::{self, Align, Color32, Layout, RichText, Ui};

use crate::model::{
    protocol_label, query_matches, AppItem, AppKind, BlocklistGroup, BlocklistState, Direction,
    Profile, Rule, RuleAction, RuleOrigin, APP_NAME, APP_VERSION,
};
use crate::rules::parse_rule_list;

use super::theme;

pub const PROTOCOLS: [u8; 10] = [0, 6, 17, 1, 58, 2, 47, 50, 51, 41];
pub const TIMERS: [(u64, &str); 8] = [
    (5 * 60, "5 minutes"),
    (10 * 60, "10 minutes"),
    (30 * 60, "30 minutes"),
    (60 * 60, "1 hour"),
    (2 * 60 * 60, "2 hours"),
    (4 * 60 * 60, "4 hours"),
    (12 * 60 * 60, "12 hours"),
    (24 * 60 * 60, "1 day"),
];

pub enum Dialog {
    Rule(RuleDraft),
    App(usize),
    Settings,
    About,
    Confirm(bool),
}

/// What the open dialog asks the window to do this frame.
pub enum Effect {
    None,
    Close,
    /// The profile was edited in place.
    Changed,
    SaveRule(Box<Rule>, Option<usize>),
    SetFilters(bool, bool),
}

pub struct RuleDraft {
    index: Option<usize>,
    readonly: bool,
    rule: Rule,
    app_filter: String,
}

impl RuleDraft {
    pub fn new(apps: Vec<String>) -> Self {
        Self {
            index: None,
            readonly: false,
            rule: Rule {
                name: String::new(),
                remote: String::new(),
                local: String::new(),
                direction: Direction::Outbound,
                action: RuleAction::Permit,
                protocol: 0,
                enabled: true,
                origin: RuleOrigin::User,
                apps,
                services: false,
                kernel: false,
                readonly: false,
            },
            app_filter: String::new(),
        }
    }

    pub fn edit(index: usize, rule: &Rule) -> Self {
        Self {
            index: Some(index),
            readonly: rule.readonly || rule.origin != RuleOrigin::User,
            rule: rule.clone(),
            app_filter: String::new(),
        }
    }

    /// Why the rule cannot be saved yet, if anything.
    fn problem(&self) -> Option<String> {
        let rule = &self.rule;
        for text in [&rule.remote, &rule.local] {
            if let Err(err) = parse_rule_list(text) {
                return Some(format!("Syntax error in rule! {}", err.0));
            }
        }
        if rule.name.trim().is_empty() {
            return Some("Enter a rule name.".into());
        }
        let empty = rule.remote.trim().is_empty()
            && rule.local.trim().is_empty()
            && rule.protocol == 0
            && rule.apps.is_empty()
            && !rule.services
            && !rule.kernel;
        empty.then(|| "Add an address, port, protocol, or app.".into())
    }
}

fn window(title: &str) -> egui::Window<'_> {
    egui::Window::new(title)
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
}

pub fn rule_editor(ctx: &egui::Context, draft: &mut RuleDraft, profile: &Profile, accent: Color32) -> Effect {
    let mut effect = Effect::None;
    let mut open = true;
    let title = match (draft.index, draft.readonly) {
        (None, _) => "Create rule",
        (Some(_), true) => "Rule",
        (Some(_), false) => "Edit rule",
    };
    window(title).open(&mut open).default_width(560.0).show(ctx, |ui| {
        ui.set_width(560.0);
        let readonly = draft.readonly;
        let rule = &mut draft.rule;
        egui::Grid::new("rule_fields")
            .num_columns(2)
            .spacing([14.0, 10.0])
            .min_col_width(80.0)
            .show(ui, |ui| {
                ui.add_enabled_ui(!readonly, |ui| ui.label("Name"));
                ui.add_enabled(!readonly, egui::TextEdit::singleline(&mut rule.name).desired_width(f32::INFINITY));
                ui.end_row();

                ui.label("Action");
                ui.add_enabled_ui(!readonly, |ui| {
                    ui.horizontal(|ui| {
                        ui.radio_value(&mut rule.action, RuleAction::Permit, "Allow");
                        ui.radio_value(&mut rule.action, RuleAction::Block, "Block");
                    });
                });
                ui.end_row();

                ui.label("Direction");
                ui.add_enabled_ui(!readonly, |ui| {
                    egui::ComboBox::from_id_salt("direction")
                        .selected_text(rule.direction.label())
                        .width(160.0)
                        .show_ui(ui, |ui| {
                            for dir in [Direction::Outbound, Direction::Inbound, Direction::Any] {
                                ui.selectable_value(&mut rule.direction, dir, dir.label());
                            }
                        });
                });
                ui.end_row();

                ui.label("Protocol");
                ui.add_enabled_ui(!readonly, |ui| {
                    egui::ComboBox::from_id_salt("protocol")
                        .selected_text(protocol_label(rule.protocol))
                        .width(160.0)
                        .show_ui(ui, |ui| {
                            for proto in PROTOCOLS {
                                ui.selectable_value(&mut rule.protocol, proto, protocol_label(proto));
                            }
                        });
                });
                ui.end_row();

                ui.label("Remote");
                ui.add_enabled(
                    !readonly,
                    egui::TextEdit::singleline(&mut rule.remote)
                        .hint_text(if readonly { "" } else { "192.168.0.0/16; 10.0.0.1-10.0.0.9; 443; [::1]" })
                        .desired_width(f32::INFINITY),
                );
                ui.end_row();

                ui.label("Local");
                ui.add_enabled(
                    !readonly,
                    egui::TextEdit::singleline(&mut rule.local)
                        .hint_text(if readonly { "" } else { "Ports or addresses, separated by ;" })
                        .desired_width(f32::INFINITY),
                );
                ui.end_row();
            });

        ui.add_space(10.0);
        ui.horizontal(|ui| {
            ui.label(RichText::new("Apps").font(theme::semibold(13.0)));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut draft.app_filter)
                        .hint_text("Find app")
                        .desired_width(200.0),
                );
            });
        });
        ui.label(
            RichText::new("If there is no apps selected, then rule will be applied for all apps.")
                .small()
                .color(theme::TEXT_MUTED),
        );
        ui.add_space(4.0);
        app_checklist(ui, &mut draft.rule, profile, &draft.app_filter, readonly);

        ui.add_space(8.0);
        ui.checkbox(&mut draft.rule.enabled, "Enable this rule");

        let problem = draft.problem();
        ui.add_space(6.0);
        ui.separator();
        ui.horizontal(|ui| {
            if let Some(problem) = &problem {
                ui.label(RichText::new(problem).color(theme::DANGER));
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui.button("Cancel").clicked() {
                    effect = Effect::Close;
                }
                let can_save = problem.is_none() || draft.readonly;
                let save = egui::Button::new(RichText::new("Save").color(theme::text_on(accent))).fill(accent);
                if ui.add_enabled(can_save, save).clicked() {
                    let mut rule = draft.rule.clone();
                    rule.name = rule.name.trim().to_string();
                    rule.remote = rule.remote.trim().to_string();
                    rule.local = rule.local.trim().to_string();
                    effect = Effect::SaveRule(Box::new(rule), draft.index);
                }
            });
        });
    });
    if !open {
        effect = Effect::Close;
    }
    effect
}

fn app_checklist(ui: &mut Ui, rule: &mut Rule, profile: &Profile, filter: &str, readonly: bool) {
    egui::Frame::NONE
        .fill(theme::SURFACE)
        .stroke(egui::Stroke::new(1.0_f32, theme::BORDER))
        .corner_radius(6)
        .inner_margin(6)
        .show(ui, |ui| {
            egui::ScrollArea::vertical()
                .max_height(190.0)
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    ui.add_enabled_ui(!readonly, |ui| {
                        if rule.kernel || rule.services {
                            ui.checkbox(&mut rule.kernel, "System (kernel)");
                            ui.checkbox(&mut rule.services, "All services");
                        }
                        let mut apps: Vec<&AppItem> = profile
                            .apps
                            .iter()
                            .filter(|app| query_matches(filter, false, &[&app.display_name, &app.path]))
                            .collect();
                        apps.sort_by_cached_key(|app| (app_order(app), app.display_name.to_lowercase()));
                        for app in apps {
                            let position = rule.apps.iter().position(|p| p.eq_ignore_ascii_case(&app.path));
                            let mut checked = position.is_some();
                            let label = format!("{}  ·  {}", app.display_name, kind_label(app.kind));
                            if ui.checkbox(&mut checked, label).on_hover_text(&app.path).changed() {
                                match position {
                                    Some(i) => {
                                        rule.apps.remove(i);
                                    }
                                    None => rule.apps.push(app.path.clone()),
                                }
                            }
                        }
                        // Paths in the rule that are not in the app list any more.
                        let known = |path: &String| profile.apps.iter().any(|a| a.path.eq_ignore_ascii_case(path));
                        let mut remove = None;
                        for (i, path) in rule.apps.iter().enumerate().filter(|(_, p)| !known(p)) {
                            let mut checked = true;
                            if ui.checkbox(&mut checked, format!("{path}  ·  not found")).changed() {
                                remove = Some(i);
                            }
                        }
                        if let Some(i) = remove {
                            rule.apps.remove(i);
                        }
                    });
                });
        });
}

fn app_order(app: &AppItem) -> u8 {
    match app.kind {
        AppKind::System => 0,
        AppKind::Regular => 1,
        AppKind::Service => 2,
        AppKind::Uwp => 3,
    }
}

fn kind_label(kind: AppKind) -> &'static str {
    match kind {
        AppKind::Regular => "app",
        AppKind::System => "system",
        AppKind::Service => "service",
        AppKind::Uwp => "UWP",
    }
}

pub fn app_properties(ctx: &egui::Context, index: usize, profile: &mut Profile) -> Effect {
    let mut effect = Effect::None;
    let mut open = true;
    let Some(app) = profile.apps.get(index).cloned() else {
        return Effect::Close;
    };
    window("App").open(&mut open).show(ctx, |ui| {
        ui.set_width(480.0);
        ui.label(RichText::new(&app.display_name).font(theme::semibold(16.0)));
        ui.label(RichText::new(&app.path).small().color(theme::TEXT_MUTED));
        ui.add_space(10.0);

        let item = &mut profile.apps[index];
        egui::Grid::new("app_fields").num_columns(2).spacing([14.0, 10.0]).show(ui, |ui| {
            ui.label("Comment");
            if ui
                .add(egui::TextEdit::singleline(&mut item.comment).desired_width(f32::INFINITY))
                .lost_focus()
            {
                effect = Effect::Changed;
            }
            ui.end_row();

            ui.label("Access");
            if ui.checkbox(&mut item.enabled, "Allow network access").changed() {
                if !item.enabled {
                    item.timer_until = 0;
                }
                effect = Effect::Changed;
            }
            ui.end_row();

            ui.label("");
            if ui.checkbox(&mut item.pinned, "Keep in list (pinned)").changed() {
                effect = Effect::Changed;
            }
            ui.end_row();

            ui.label("Timer");
            let current = if item.has_timer() {
                format!("Until {}", super::shell::format_time(item.timer_until))
            } else {
                "Off".into()
            };
            egui::ComboBox::from_id_salt("timer").selected_text(current).width(200.0).show_ui(ui, |ui| {
                if ui.selectable_label(!item.has_timer(), "Off").clicked() {
                    item.timer_until = 0;
                    effect = Effect::Changed;
                }
                for (secs, label) in TIMERS {
                    if ui.selectable_label(false, label).clicked() {
                        item.enabled = true;
                        item.timer_until = crate::model::now_unix() + secs;
                        effect = Effect::Changed;
                    }
                }
            });
            ui.end_row();
        });

        ui.add_space(10.0);
        ui.label(RichText::new("User rules").font(theme::semibold(13.0)));
        let users: Vec<usize> = (0..profile.rules.len())
            .filter(|i| profile.rules[*i].origin == RuleOrigin::User)
            .collect();
        egui::Frame::NONE
            .fill(theme::SURFACE)
            .stroke(egui::Stroke::new(1.0_f32, theme::BORDER))
            .corner_radius(6)
            .inner_margin(6)
            .show(ui, |ui| {
                egui::ScrollArea::vertical().max_height(160.0).auto_shrink([false, true]).show(ui, |ui| {
                    if users.is_empty() {
                        ui.label(RichText::new("No user rules yet.").color(theme::TEXT_MUTED));
                    }
                    for i in users {
                        let rule = &mut profile.rules[i];
                        let position = rule.apps.iter().position(|p| p.eq_ignore_ascii_case(&app.path));
                        let mut checked = position.is_some();
                        let label = format!("{}  ·  {}", rule.name, rule.action.label());
                        if ui.checkbox(&mut checked, label).changed() {
                            match position {
                                Some(p) => {
                                    rule.apps.remove(p);
                                }
                                None => rule.apps.push(app.path.clone()),
                            }
                            effect = Effect::Changed;
                        }
                    }
                });
            });

        ui.add_space(8.0);
        ui.horizontal(|ui| {
            if app.kind == AppKind::Regular && ui.button("Open file location").clicked() {
                super::shell::reveal(&app.path);
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui.button("Close").clicked() {
                    effect = Effect::Close;
                }
            });
        });
    });
    if !open {
        effect = Effect::Close;
    }
    effect
}

pub fn settings(ctx: &egui::Context, profile: &mut Profile) -> Effect {
    let mut effect = Effect::None;
    let mut open = true;
    window("Settings").open(&mut open).show(ctx, |ui| {
        ui.set_width(440.0);
        let s = &mut profile.settings;
        section(ui, "Filtering");
        let mut changed = false;
        changed |= ui.checkbox(&mut s.allow_loopback, "Allow loopback connections").changed();
        changed |= ui.checkbox(&mut s.allow_ipv6, "Allow IPv6 neighbor discovery and 6to4").changed();
        changed |= ui.checkbox(&mut s.allow_lan, "Allow local network (LAN)").changed();
        changed |= ui
            .checkbox(&mut s.user_allows_override_blocklist, "User rules take priority over the blocklist")
            .changed();

        section(ui, "Blocklist");
        egui::Grid::new("blocklist").num_columns(2).spacing([14.0, 8.0]).show(ui, |ui| {
            for group in BlocklistGroup::all() {
                ui.label(group.label());
                let mut state = s.blocklist(group);
                ui.horizontal(|ui| {
                    for option in BlocklistState::all() {
                        ui.selectable_value(&mut state, option, option.label());
                    }
                });
                if state != s.blocklist(group) {
                    s.set_blocklist(group, state);
                    changed = true;
                }
                ui.end_row();
            }
        });

        section(ui, "Interface");
        changed |= ui.checkbox(&mut s.always_on_top, "Always on top").changed();
        changed |= ui.checkbox(&mut s.show_filenames_only, "Show filenames only").changed();
        changed |= ui.checkbox(&mut s.log_to_file, "Write a log file (simplewall.csv)").changed();

        if let Some(path) = crate::profile::user_path() {
            ui.add_space(10.0);
            ui.label(RichText::new(format!("Profile: {}", path.display())).small().color(theme::TEXT_MUTED));
        }
        ui.add_space(6.0);
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if ui.button("Close").clicked() {
                effect = Effect::Close;
            }
        });
        if changed {
            effect = Effect::Changed;
        }
    });
    if !open {
        effect = Effect::Close;
    }
    effect
}

fn section(ui: &mut Ui, title: &str) {
    ui.add_space(6.0);
    ui.label(RichText::new(title).font(theme::semibold(13.0)).color(theme::TEXT));
    ui.add_space(2.0);
}

pub fn about(ctx: &egui::Context, logo: &egui::TextureHandle) -> Effect {
    let mut effect = Effect::None;
    let mut open = true;
    window("About").open(&mut open).show(ctx, |ui| {
        ui.set_width(380.0);
        ui.horizontal(|ui| {
            ui.add(egui::Image::new((logo.id(), egui::vec2(48.0, 48.0))));
            ui.vertical(|ui| {
                ui.label(RichText::new(format!("{APP_NAME} {APP_VERSION}")).font(theme::semibold(18.0)));
                ui.label(RichText::new("Rust port of simplewall by Henry++").color(theme::TEXT_MUTED));
                ui.label(RichText::new("GNU General Public License v3").small().color(theme::TEXT_MUTED));
            });
        });
        ui.add_space(10.0);
        ui.hyperlink_to("github.com/NitroDiesel/simplewall", "https://github.com/NitroDiesel/simplewall");
        ui.hyperlink_to("github.com/henrypp/simplewall", "https://github.com/henrypp/simplewall");
        ui.add_space(6.0);
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if ui.button("Close").clicked() {
                effect = Effect::Close;
            }
        });
    });
    if !open {
        effect = Effect::Close;
    }
    effect
}

/// The same questions the C build asks before it changes filtering.
pub fn confirm(ctx: &egui::Context, enable: bool, accent: Color32) -> Effect {
    let mut effect = Effect::None;
    let modal = egui::Modal::new(egui::Id::new("confirm_filters")).show(ctx, |ui| {
        ui.set_width(420.0);
        let (title, body) = if enable {
            (
                "Enable filtering?",
                "This will deny network access to apps as defined by the current configuration. Continue?",
            )
        } else {
            (
                "Disable filtering?",
                "This will restore network access for all apps that are currently blocked. Continue?",
            )
        };
        ui.label(RichText::new(title).font(theme::semibold(16.0)));
        ui.add_space(6.0);
        ui.label(body);
        ui.add_space(14.0);
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            let label = if enable { "Enable" } else { "Disable" };
            let primary = egui::Button::new(RichText::new(label).color(theme::text_on(accent))).fill(accent);
            if ui.add(primary).clicked() {
                effect = Effect::SetFilters(enable, false);
            }
            if enable && ui.button("Until reboot").clicked() {
                effect = Effect::SetFilters(true, true);
            }
            if ui.button("Cancel").clicked() {
                effect = Effect::Close;
            }
        });
    });
    if modal.should_close() && matches!(effect, Effect::None) {
        effect = Effect::Close;
    }
    effect
}
