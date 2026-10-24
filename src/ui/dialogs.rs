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
    Confirm(Ask),
}

/// What the open dialog asks the window to do this frame.
pub enum Effect {
    None,
    Close,
    /// The profile was edited in place; save and reinstall filters.
    Changed,
    /// A setting that does not affect filters changed; save only.
    Saved,
    Error(String),
    SaveRule(Box<Rule>, Option<usize>),
    /// The confirmation was accepted; the flag is "until reboot" for filtering.
    Accept(Ask, bool),
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

    /// A rule for one blocked connection, from a notification.
    pub fn for_connection(app: String, remote: String, protocol: u8, inbound: bool) -> Self {
        let mut draft = Self::new(vec![app]);
        draft.rule.remote = remote;
        draft.rule.protocol = protocol;
        if inbound {
            draft.rule.direction = Direction::Inbound;
        }
        draft
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
                .color(theme::text_muted()),
        );
        ui.add_space(4.0);
        // Built-in rules keep their addresses, but apps can be assigned, as in the C build.
        app_checklist(ui, &mut draft.rule, profile, &draft.app_filter, false);

        ui.add_space(8.0);
        ui.checkbox(&mut draft.rule.enabled, "Enable this rule");

        let problem = draft.problem();
        ui.add_space(6.0);
        ui.separator();
        ui.horizontal(|ui| {
            if let Some(problem) = &problem {
                ui.label(RichText::new(problem).color(theme::danger()));
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
        .fill(theme::surface())
        .stroke(egui::Stroke::new(1.0_f32, theme::border()))
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
        ui.label(RichText::new(&app.path).small().color(theme::text_muted()));
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
                    // Ending a running timer blocks the app again (henrypp/simplewall#2159).
                    if item.has_timer() {
                        item.enabled = false;
                    }
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
            .fill(theme::surface())
            .stroke(egui::Stroke::new(1.0_f32, theme::border()))
            .corner_radius(6)
            .inner_margin(6)
            .show(ui, |ui| {
                egui::ScrollArea::vertical().max_height(160.0).auto_shrink([false, true]).show(ui, |ui| {
                    if users.is_empty() {
                        ui.label(RichText::new("No user rules yet.").color(theme::text_muted()));
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

/// Task Scheduler state for the General page. Reading it runs schtasks, so the
/// window reads it once, when Settings first opens.
#[derive(Clone, Copy)]
pub struct Startup {
    pub autorun: bool,
    pub skip_uac: bool,
}

impl Startup {
    pub fn read() -> Self {
        Self {
            autorun: crate::autorun::autorun_enabled(),
            skip_uac: crate::autorun::skip_uac_enabled(),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Default)]
enum Page {
    #[default]
    General,
    Appearance,
    Filters,
    Blocklist,
    Security,
    Connections,
    Notifications,
    Logging,
}

impl Page {
    const ALL: [Page; 8] = [
        Page::General,
        Page::Appearance,
        Page::Filters,
        Page::Blocklist,
        Page::Security,
        Page::Connections,
        Page::Notifications,
        Page::Logging,
    ];

    fn label(self) -> &'static str {
        match self {
            Page::General => "General",
            Page::Appearance => "Appearance",
            Page::Filters => "Filters",
            Page::Blocklist => "Blocklist",
            Page::Security => "Security",
            Page::Connections => "Connections",
            Page::Notifications => "Notifications",
            Page::Logging => "Packets log",
        }
    }
}

/// Settings with a page list on the left, like the C build's settings dialog.
/// Filter options return `Changed` (save and reinstall); the rest return `Saved`.
pub fn settings(ctx: &egui::Context, profile: &mut Profile, startup: &mut Startup) -> Effect {
    let mut effect = Effect::None;
    let mut open = true;
    let page_id = egui::Id::new("settings_page");
    let mut page: Page = ctx.data(|d| d.get_temp(page_id)).unwrap_or_default();
    window("Settings").open(&mut open).show(ctx, |ui| {
        ui.set_width(620.0);
        ui.horizontal_top(|ui| {
            ui.vertical(|ui| {
                ui.set_width(140.0);
                for p in Page::ALL {
                    let selected = page == p;
                    let text = RichText::new(p.label()).color(if selected { theme::text() } else { theme::text_muted() });
                    if ui.add_sized([140.0, 28.0], egui::SelectableLabel::new(selected, text)).clicked() {
                        page = p;
                    }
                }
            });
            // A fixed-height divider; ui.separator() here would stretch the window to the screen.
            let (line, _) = ui.allocate_exact_size(egui::vec2(9.0, 400.0), egui::Sense::hover());
            ui.painter().vline(line.center().x, line.y_range(), egui::Stroke::new(1.0_f32, theme::border()));
            ui.vertical(|ui| {
                ui.set_width(450.0);
                let s = &mut profile.settings;
                let mut filters = false;
                let mut saved = false;
                // A fixed height, so the window does not jump between pages or outgrow the main window.
                egui::ScrollArea::vertical()
                    .id_salt(page.label())
                    .min_scrolled_height(400.0)
                    .max_height(400.0)
                    .auto_shrink([false, false])
                    .show(ui, |ui| match page {
                    Page::General => {
                        section(ui, "Startup");
                        let mut autorun = startup.autorun;
                        if ui.checkbox(&mut autorun, "Load on system startup").changed() {
                            match crate::autorun::set_autorun(autorun) {
                                Ok(()) => startup.autorun = autorun,
                                Err(err) => effect = Effect::Error(err),
                            }
                        }
                        saved |= ui.checkbox(&mut s.start_minimized, "Start minimized").changed();
                        let mut skip_uac = startup.skip_uac;
                        if ui.checkbox(&mut skip_uac, "Skip UAC warning").changed() {
                            match crate::autorun::set_skip_uac(skip_uac) {
                                Ok(()) => startup.skip_uac = skip_uac,
                                Err(err) => effect = Effect::Error(err),
                            }
                        }
                        hint(ui, "Both use Task Scheduler with highest privileges, so no UAC prompt appears.");
                        section(ui, "Window");
                        saved |= ui.checkbox(&mut s.always_on_top, "Always on top").changed();
                        saved |= ui.checkbox(&mut s.show_filenames_only, "Show filenames only").changed();
                        saved |= ui.checkbox(&mut s.confirm_exit, "Ask before exiting while filters are on").changed();
                        if let Some(path) = crate::profile::user_path() {
                            ui.add_space(10.0);
                            hint(ui, &format!("Profile: {}", path.display()));
                        }
                    }
                    Page::Appearance => {
                        section(ui, "Theme");
                        ui.horizontal(|ui| {
                            for (value, label) in [(0, "Same as Windows"), (1, "Dark"), (2, "Light")] {
                                saved |= ui.radio_value(&mut s.theme, value, label).changed();
                            }
                        });
                        section(ui, "Highlighting");
                        saved |= ui.checkbox(&mut s.highlighting, "Color list rows").changed();
                        ui.add_enabled_ui(s.highlighting, |ui| {
                            let rows: [(&mut bool, &str, Color32); 6] = [
                                (&mut s.highlight_invalid, "Missing files and rules with errors", theme::FILL_INVALID),
                                (&mut s.highlight_connection, "Apps with an active connection", theme::FILL_CONNECTION),
                                (&mut s.highlight_signed, "Signed apps", theme::FILL_SIGNED),
                                (&mut s.highlight_special, "Rules for specific apps", theme::FILL_SPECIAL),
                                (&mut s.highlight_undelete, "Pinned apps", theme::FILL_UNDELETE),
                                (&mut s.highlight_system, "System apps and services", theme::FILL_SYSTEM),
                            ];
                            for (value, label, color) in rows {
                                ui.horizontal(|ui| {
                                    let (rect, _) = ui.allocate_exact_size(egui::vec2(14.0, 14.0), egui::Sense::hover());
                                    ui.painter().rect_filled(rect, 3.0, color);
                                    saved |= ui.checkbox(value, label).changed();
                                });
                            }
                        });
                    }
                    Page::Filters => {
                        section(ui, "Allow");
                        filters |= ui.checkbox(&mut s.allow_loopback, "Allow loopback connections").changed();
                        filters |= ui.checkbox(&mut s.allow_ipv6, "Allow IPv6 neighbor discovery and 6to4").changed();
                        filters |= ui.checkbox(&mut s.allow_lan, "Allow local network (LAN)").changed();
                        filters |= ui
                            .checkbox(&mut s.user_allows_override_blocklist, "User rules take priority over the blocklist")
                            .changed();
                        section(ui, "Block");
                        filters |= ui.checkbox(&mut s.block_outbound, "Block outbound connections").changed();
                        filters |= ui.checkbox(&mut s.block_inbound, "Block inbound connections").changed();
                        filters |= ui
                            .checkbox(&mut s.stealth_mode, "Use stealth mode (do not answer port scans)")
                            .changed();
                        filters |= ui
                            .checkbox(&mut s.boot_time_filters, "Install boot-time filters")
                            .on_hover_text("Filter from the moment Windows starts, before the firewall engine loads.")
                            .changed();
                        ui.add_enabled_ui(s.boot_time_filters, |ui| {
                            filters |= ui
                                .checkbox(&mut s.allow_ip_forwarding, "Allow IP forwarding")
                                .on_hover_text("Needed for Mobile Hotspot, Internet Connection Sharing, and NAT for virtual machines.")
                                .changed();
                        });
                        filters |= ui
                            .checkbox(&mut s.internal_rules_disabled, "Disable internal rules")
                            .on_hover_text("Install only your own rules; the system rules and blocklist are skipped.")
                            .changed();
                    }
                    Page::Blocklist => {
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
                                    filters = true;
                                }
                                ui.end_row();
                            }
                        });
                    }
                    Page::Security => {
                        section(ui, "Files");
                        saved |= ui.checkbox(&mut s.check_signatures, "Check digital signatures").changed();
                        ui.add_enabled_ui(s.check_signatures, |ui| {
                            saved |= ui
                                .checkbox(&mut s.check_revocation, "Check certificate revocation online (slower)")
                                .changed();
                        });
                        hint(ui, "Signed apps are shown in green, with the signer in the tooltip.");
                        ui.add_space(6.0);
                        saved |= ui
                            .checkbox(&mut s.check_hashes, "Block an allowed app again when its file changes")
                            .changed();
                        hint(ui, "Takes a SHA-256 of each allowed app and compares it every 10 minutes.");
                    }
                    Page::Connections => {
                        section(ui, "Connections");
                        saved |= ui
                            .checkbox(&mut s.network_monitor, "Monitor connections (refresh every 2 seconds)")
                            .changed();
                        saved |= ui
                            .checkbox(&mut s.show_wait_connections, "Show connections waiting to close")
                            .changed();
                        saved |= ui
                            .checkbox(&mut s.resolve_hostnames, "Look up host names for remote addresses")
                            .changed();
                        hint(ui, "Apps with an active connection are shown in pink while monitoring is on.");
                    }
                    Page::Notifications => {
                        section(ui, "Notifications");
                        saved |= ui.checkbox(&mut s.notifications, "Enable packets notifications").changed();
                        ui.add_enabled_ui(s.notifications, |ui| {
                            saved |= ui.checkbox(&mut s.notifications_sound, "Enable notifications sound").changed();
                            saved |= ui
                                .checkbox(
                                    &mut s.notifications_fullscreen_silent,
                                    "Enable silent-mode when full screen app in foreground",
                                )
                                .changed();
                            ui.horizontal(|ui| {
                                ui.label("Do not repeat for the same app within");
                                saved |= ui
                                    .add(egui::DragValue::new(&mut s.notifications_timeout).range(0..=86_400).suffix(" s"))
                                    .changed();
                            });
                        });
                        hint(ui, "A notification appears when an app that is not allowed tries to connect.");
                    }
                    Page::Logging => {
                        section(ui, "Packets log");
                        saved |= ui.checkbox(&mut s.log_to_file, "Enable packets logging to a file").changed();
                        ui.add_enabled_ui(s.log_to_file, |ui| {
                            ui.horizontal(|ui| {
                                ui.label("Start the file over at");
                                saved |= ui
                                    .add(egui::DragValue::new(&mut s.log_size_limit_kb).range(0..=1_048_576).suffix(" KB"))
                                    .changed();
                            });
                        });
                        saved |= ui
                            .checkbox(&mut s.log_ui, "Enable packets logging interface (session only)")
                            .changed();
                        hint(ui, &format!("Log file: {}", crate::log::log_path().display()));
                    }
                });
                if filters {
                    effect = Effect::Changed;
                } else if saved && matches!(effect, Effect::None) {
                    effect = Effect::Saved;
                }
            });
        });
        ui.add_space(6.0);
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if ui.button("Close").clicked() {
                effect = Effect::Close;
            }
        });
    });
    ctx.data_mut(|d| d.insert_temp(page_id, page));
    if !open {
        effect = Effect::Close;
    }
    effect
}

fn hint(ui: &mut Ui, text: &str) {
    ui.label(RichText::new(text).small().color(theme::text_muted()));
}

fn section(ui: &mut Ui, title: &str) {
    ui.add_space(6.0);
    ui.label(RichText::new(title).font(theme::semibold(13.0)).color(theme::text()));
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
                ui.label(RichText::new("Rust port of simplewall by Henry++").color(theme::text_muted()));
                ui.label(RichText::new("GNU General Public License v3").small().color(theme::text_muted()));
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

/// A question asked before something hard to undo.
#[derive(Clone, Copy)]
pub enum Ask {
    /// Enable (true) or disable filtering, with the C build's wording.
    Filters(bool),
    /// Purge this many unused apps (henrypp/simplewall#2109: say what it does).
    PurgeUnused(usize),
    ClearLog,
    /// Close while this many app timers are still running.
    CloseWithTimers(usize),
    /// Exit while filters are on (ConfirmExit2).
    Exit,
}

pub fn confirm(ctx: &egui::Context, ask: Ask, accent: Color32) -> Effect {
    let mut effect = Effect::None;
    let (title, body, action) = match ask {
        Ask::Filters(true) => (
            "Enable filtering?".to_string(),
            "This will deny network access to apps as defined by the current configuration. Continue?".to_string(),
            "Enable",
        ),
        Ask::Filters(false) => (
            "Disable filtering?".to_string(),
            "This will restore network access for all apps that are currently blocked. Continue?".to_string(),
            "Disable",
        ),
        Ask::PurgeUnused(count) => (
            format!("Remove {count} unused apps?"),
            "This removes apps that are missing from disk, and apps that are not allowed, pinned, or used by any rule. Running apps come back on the next refresh.".to_string(),
            "Remove",
        ),
        Ask::ClearLog => (
            "Clear the log?".to_string(),
            "This deletes simplewall.csv and empties the Packets log.".to_string(),
            "Clear",
        ),
        Ask::Exit => (
            "Exit simplewall?".to_string(),
            "Installed filters will continue to work even if you exit. Continue?".to_string(),
            "Exit",
        ),
        Ask::CloseWithTimers(count) => (
            "End running timers?".to_string(),
            format!(
                "Timers only run while simplewall is open. Closing now blocks the {count} app(s) that have a timer, so they do not keep network access."
            ),
            "End timers and close",
        ),
    };
    let modal = egui::Modal::new(egui::Id::new("confirm")).show(ctx, |ui| {
        ui.set_width(420.0);
        ui.label(RichText::new(title).font(theme::semibold(16.0)));
        ui.add_space(6.0);
        ui.label(body);
        // "Do not ask again" for the exit question, as the C build offers.
        let quiet_id = egui::Id::new("confirm_quiet");
        let mut quiet = ui.data(|d| d.get_temp::<bool>(quiet_id)).unwrap_or(false);
        if matches!(ask, Ask::Exit) {
            ui.add_space(8.0);
            ui.checkbox(&mut quiet, "Do not ask again");
            ui.data_mut(|d| d.insert_temp(quiet_id, quiet));
        }
        ui.add_space(14.0);
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            let primary = egui::Button::new(RichText::new(action).color(theme::text_on(accent))).fill(accent);
            if ui.add(primary).clicked() {
                effect = Effect::Accept(ask, matches!(ask, Ask::Exit) && quiet);
            }
            if matches!(ask, Ask::Filters(true)) && ui.button("Until reboot").clicked() {
                effect = Effect::Accept(ask, true);
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
