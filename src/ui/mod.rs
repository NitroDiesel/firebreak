//! Main window with the C build's layout: menu bar, toolbar with the search box
//! on the right, eight tabs, a grouped report list, and a three-part status bar.
//! Filter installs run on a worker thread so the list never stalls.

mod dialogs;
mod list;
mod shell;
mod theme;
mod view;

use std::collections::HashSet;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::{Duration, Instant};

use eframe::egui::{
    self, emath::easing, pos2, vec2, Align, Color32, CornerRadius, Event, FontId, Id, Key, Layout,
    Margin, Modifiers, Rangef, Rect, Response, Sense, Stroke, TextureHandle, Ui,
};

use crate::apps;
use crate::log::{self, Endpoint};
use crate::model::{now_unix, AppItem, AppKind, BlocklistGroup, BlocklistState, Profile, RuleOrigin};
use crate::profile;
use crate::wfp::{self, Packet};

use dialogs::{Dialog, Effect, RuleDraft, TIMERS};
use list::{FileIcons, Line, List, Sort};
use theme::Icons;
use view::Tab;

const FIND_ID: &str = "find";
const NOTICE_SECONDS: u64 = 6;
const TAB_SLIDE: f64 = 0.2;
const HOVER_FADE: f32 = 0.12;

enum Job {
    Install { seq: u64, profile: Box<Profile>, temporary: bool },
    Uninstall { seq: u64 },
}

enum Reply {
    Filters { seq: u64, enabled: bool, result: Result<String, String> },
    Packets(Result<Vec<Packet>, String>),
}

/// One thread applies filters. Queued jobs collapse to the newest, since each
/// install describes the whole state.
struct Worker {
    jobs: Sender<Job>,
    replies: Receiver<Reply>,
    reply_tx: Sender<Reply>,
    sent: u64,
    done: u64,
}

impl Worker {
    fn spawn(ctx: egui::Context) -> Self {
        let (jobs, job_rx) = channel::<Job>();
        let (reply_tx, replies) = channel();
        let tx = reply_tx.clone();
        std::thread::spawn(move || {
            while let Ok(mut job) = job_rx.recv() {
                while let Ok(next) = job_rx.try_recv() {
                    job = next;
                }
                let reply = match job {
                    Job::Install { seq, profile, temporary } => Reply::Filters {
                        seq,
                        enabled: true,
                        result: wfp::install(&profile, temporary),
                    },
                    Job::Uninstall { seq } => Reply::Filters {
                        seq,
                        enabled: false,
                        result: wfp::uninstall(),
                    },
                };
                if tx.send(reply).is_err() {
                    break;
                }
                ctx.request_repaint();
            }
        });
        Self { jobs, replies, reply_tx, sent: 0, done: 0 }
    }

    fn busy(&self) -> bool {
        self.done < self.sent
    }
}

struct Notice {
    text: String,
    error: bool,
    until: Instant,
}

/// Accent underline under the active tab; slides between tabs.
struct Underline {
    tab: Tab,
    drawn: Rangef,
    from: Rangef,
    start: f64,
}

enum Action {
    Find,
    Refresh,
    Settings,
    About,
    NextTab,
    PrevTab,
    PurgeUnused,
    PurgeTimers,
    Delete,
    Open,
    Toggle,
    Move(i32),
    Explore,
    Copy,
}

pub struct SimplewallApp {
    profile: Profile,
    accent: Color32,
    icons: Icons,
    files: FileIcons,
    tab: Tab,
    query: String,
    sorts: [Sort; 8],
    collapsed: [HashSet<u8>; 8],
    selected: [Option<usize>; 8],
    lines: Vec<Line>,
    dirty: bool,
    scroll_to: Option<usize>,
    unused: usize,
    timers: usize,
    connections: Vec<Endpoint>,
    packets: Vec<Packet>,
    packets_state: Option<String>,
    packets_cleared_at: u64,
    filters_on: bool,
    worker: Worker,
    notice: Option<Notice>,
    dialog: Option<Dialog>,
    underline: Option<Underline>,
}

impl SimplewallApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let ctx = &cc.egui_ctx;
        let accent = theme::accent();
        theme::apply(ctx, accent);
        let mut profile = profile::load();
        profile.apps = apps::merge(&profile.apps, apps::enumerate());
        if profile.settings.always_on_top {
            ctx.send_viewport_cmd(egui::ViewportCommand::WindowLevel(egui::WindowLevel::AlwaysOnTop));
        }
        let filters_on = wfp::filters_installed().unwrap_or(false);
        let sort = Sort { column: 0, descending: false };
        let mut app = Self {
            profile,
            accent,
            icons: Icons::load(ctx),
            files: FileIcons::default(),
            tab: Tab::Apps,
            query: String::new(),
            sorts: [sort; 8],
            collapsed: Default::default(),
            selected: [None; 8],
            lines: Vec::new(),
            dirty: true,
            scroll_to: None,
            unused: 0,
            timers: 0,
            connections: Vec::new(),
            packets: Vec::new(),
            packets_state: None,
            packets_cleared_at: 0,
            filters_on,
            worker: Worker::spawn(ctx.clone()),
            notice: None,
            dialog: None,
            underline: None,
        };
        // Packets log sorts newest first, as in the C build.
        app.sorts[Tab::Packets.index()] = Sort { column: 1, descending: true };
        app.save();
        app
    }

    // ---- state changes -------------------------------------------------

    fn save(&mut self) {
        if let Err(err) = profile::save(&self.profile) {
            self.notify(format!("Could not save the profile: {err}"), true);
        }
    }

    /// Persist, refresh the list, and reinstall filters when they are on.
    fn changed(&mut self) {
        self.save();
        self.dirty = true;
        if self.filters_on {
            self.send_install(self.profile.settings.filters_temporary);
        }
    }

    fn send_install(&mut self, temporary: bool) {
        self.worker.sent += 1;
        let job = Job::Install {
            seq: self.worker.sent,
            profile: Box::new(self.profile.clone()),
            temporary,
        };
        let _ = self.worker.jobs.send(job);
    }

    fn set_filters(&mut self, enable: bool, temporary: bool) {
        if enable {
            self.profile.settings.filters_temporary = temporary;
            self.save();
            self.send_install(temporary);
        } else {
            self.worker.sent += 1;
            let _ = self.worker.jobs.send(Job::Uninstall { seq: self.worker.sent });
        }
    }

    fn notify(&mut self, text: impl Into<String>, error: bool) {
        self.notice = Some(Notice {
            text: text.into(),
            error,
            until: Instant::now() + Duration::from_secs(NOTICE_SECONDS),
        });
    }

    fn poll_worker(&mut self) {
        while let Ok(reply) = self.worker.replies.try_recv() {
            match reply {
                Reply::Filters { seq, enabled, result } => {
                    self.worker.done = self.worker.done.max(seq);
                    match result {
                        Ok(msg) => {
                            if seq == self.worker.sent {
                                self.filters_on = enabled;
                            }
                            if msg.contains("Skipped") {
                                self.notify(msg.clone(), true);
                            }
                            if self.profile.settings.log_to_file {
                                let verb = if enabled { "install" } else { "uninstall" };
                                log::append_file(&log::log_path(), &format!("{}\t{verb}\t{msg}", now_unix()));
                            }
                        }
                        Err(err) => {
                            self.filters_on = wfp::filters_installed().unwrap_or(self.filters_on);
                            self.notify(err, true);
                        }
                    }
                }
                Reply::Packets(result) => {
                    match result {
                        Ok(packets) => {
                            let cleared = self.packets_cleared_at;
                            self.packets = packets.into_iter().filter(|p| p.time > cleared).collect();
                            self.packets_state = None;
                        }
                        Err(err) => self.packets_state = Some(err),
                    }
                    self.dirty = true;
                }
            }
        }
    }

    /// Expired timers block the app again, like `_app_timer_remove`.
    fn tick_timers(&mut self, ctx: &egui::Context) {
        let now = now_unix();
        let mut expired = Vec::new();
        let mut next: Option<u64> = None;
        for app in &mut self.profile.apps {
            if app.timer_until == 0 {
                continue;
            }
            if app.timer_until <= now {
                app.timer_until = 0;
                app.enabled = false;
                expired.push(app.display_name.clone());
            } else {
                next = Some(next.map_or(app.timer_until, |n| n.min(app.timer_until)));
            }
        }
        if !expired.is_empty() {
            self.notify(format!("Timer expired: {}", expired.join(", ")), false);
            self.changed();
        }
        if let Some(next) = next {
            ctx.request_repaint_after(Duration::from_secs(next.saturating_sub(now).max(1)));
        }
    }

    fn rebuild(&mut self) {
        let index = self.tab.index();
        let source = view::Source {
            profile: &self.profile,
            connections: &self.connections,
            packets: &self.packets,
            query: &self.query,
            sort: self.sorts[index],
            collapsed: &self.collapsed[index],
        };
        self.lines = view::build(self.tab, &source);
        self.unused = self.profile.apps.iter().filter(|a| self.profile.app_is_unused(a)).count();
        self.timers = self.profile.apps.iter().filter(|a| a.has_timer()).count();
        self.dirty = false;
    }

    fn switch_tab(&mut self, tab: Tab) {
        if tab == self.tab {
            return;
        }
        self.tab = tab;
        self.dirty = true;
        match tab {
            Tab::Connections => self.connections = log::connections(),
            Tab::Packets => self.load_packets(),
            _ => {}
        }
    }

    fn load_packets(&mut self) {
        if !self.profile.settings.log_ui {
            self.packets.clear();
            self.packets_state =
                Some("The packets log is off. Turn on \u{201C}Log to UI\u{201D} in the toolbar to collect dropped packets.".into());
            return;
        }
        self.packets_state = Some("Loading\u{2026}".into());
        let tx = self.worker.reply_tx.clone();
        std::thread::spawn(move || {
            let _ = tx.send(Reply::Packets(wfp::dropped_packets(2000)));
        });
    }

    fn refresh(&mut self) {
        self.profile.apps = apps::merge(&self.profile.apps, apps::enumerate());
        match self.tab {
            Tab::Connections => self.connections = log::connections(),
            Tab::Packets => self.load_packets(),
            _ => {}
        }
        self.save();
        self.dirty = true;
    }

    fn add_app(&mut self) {
        let Some(path) = shell::pick_executable() else {
            return;
        };
        let index = match self.profile.apps.iter().position(|a| a.path.eq_ignore_ascii_case(&path)) {
            Some(index) => index,
            None => {
                let name = std::path::Path::new(&path)
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| path.clone());
                self.profile.apps.push(AppItem::new(path, name, AppKind::Regular));
                self.profile.apps.len() - 1
            }
        };
        self.switch_tab(Tab::Apps);
        self.selected[Tab::Apps.index()] = Some(index);
        self.changed();
        self.rebuild();
        self.scroll_to = self.line_of(index);
    }

    fn purge_unused(&mut self) {
        let before = self.profile.apps.len();
        let keep: Vec<bool> = self.profile.apps.iter().map(|a| !self.profile.app_is_unused(a)).collect();
        let mut keep = keep.into_iter();
        self.profile.apps.retain(|_| keep.next().unwrap_or(true));
        let removed = before - self.profile.apps.len();
        self.clear_app_selection();
        self.notify(format!("Removed {removed} unused apps."), false);
        self.changed();
    }

    fn purge_timers(&mut self) {
        for app in self.profile.apps.iter_mut().filter(|a| a.has_timer()) {
            app.timer_until = 0;
            app.enabled = false;
        }
        self.changed();
    }

    fn clear_app_selection(&mut self) {
        for tab in [Tab::Apps, Tab::Services, Tab::Uwp] {
            self.selected[tab.index()] = None;
        }
    }

    fn clear_rule_selection(&mut self) {
        for tab in [Tab::Blocklist, Tab::System, Tab::User] {
            self.selected[tab.index()] = None;
        }
    }

    fn line_of(&self, id: usize) -> Option<usize> {
        self.lines.iter().position(|l| matches!(l, Line::Row(r) if r.id == id))
    }

    fn toggle(&mut self, id: usize) {
        if self.tab.app_kind().is_some() {
            if let Some(app) = self.profile.apps.get_mut(id) {
                app.enabled = !app.enabled;
                app.timer_until = 0;
            }
        } else if self.tab.rule_origin().is_some() {
            if let Some(rule) = self.profile.rules.get_mut(id) {
                rule.enabled = !rule.enabled;
            }
        } else {
            return;
        }
        self.changed();
    }

    fn open(&mut self, id: usize) {
        if self.tab.app_kind().is_some() && id < self.profile.apps.len() {
            self.dialog = Some(Dialog::App(id));
        } else if self.tab.rule_origin().is_some() {
            if let Some(rule) = self.profile.rules.get(id) {
                self.dialog = Some(Dialog::Rule(RuleDraft::edit(id, rule)));
            }
        }
    }

    fn delete(&mut self, id: usize) {
        if self.tab.app_kind().is_some() {
            if id < self.profile.apps.len() && self.profile.apps[id].kind != AppKind::System {
                self.profile.apps.remove(id);
                self.clear_app_selection();
                self.changed();
            }
        } else if self.tab.rule_origin().is_some() {
            if self.profile.rules.get(id).is_some_and(|r| r.origin == RuleOrigin::User) {
                self.profile.rules.remove(id);
                self.clear_rule_selection();
                self.changed();
            }
        }
    }

    fn copy_text(&self, id: usize) -> Option<String> {
        match self.tab {
            Tab::Apps | Tab::Services | Tab::Uwp => self.profile.apps.get(id).map(|a| a.path.clone()),
            Tab::Blocklist | Tab::System | Tab::User => self.profile.rules.get(id).map(|r| {
                [r.name.as_str(), r.remote.as_str(), r.local.as_str()]
                    .iter()
                    .filter(|s| !s.is_empty())
                    .copied()
                    .collect::<Vec<_>>()
                    .join("\t")
            }),
            Tab::Connections => self
                .connections
                .get(id)
                .map(|c| format!("{}\t{}\t{}\t{}\t{}", c.name, c.local, c.remote, c.proto, c.state)),
            Tab::Packets => self
                .packets
                .get(id)
                .map(|p| format!("{}\t{}\t{}", p.app, p.local, p.remote)),
        }
    }

    fn explore(&self, id: usize) {
        if self.tab.app_kind().is_none() {
            return;
        }
        if let Some(app) = self.profile.apps.get(id) {
            let path = match app.kind {
                AppKind::Regular => Some(app.path.clone()),
                AppKind::Service => apps::resolve_service_image(&app.path),
                _ => None,
            };
            if let Some(path) = path {
                shell::reveal(&apps::expand_env(&path));
            }
        }
    }

    fn set_timer(&mut self, id: usize, seconds: u64) {
        if let Some(app) = self.profile.apps.get_mut(id) {
            app.enabled = true;
            app.timer_until = now_unix() + seconds;
            self.changed();
        }
    }

    // ---- input ---------------------------------------------------------

    fn shortcuts(&mut self, ctx: &egui::Context) {
        let typing = ctx.wants_keyboard_input();
        let mut actions = Vec::new();
        ctx.input_mut(|i| {
            let ctrl_shift = Modifiers::CTRL | Modifiers::SHIFT;
            if i.consume_key(ctrl_shift, Key::Tab) {
                actions.push(Action::PrevTab);
            }
            if i.consume_key(Modifiers::CTRL, Key::Tab) {
                actions.push(Action::NextTab);
            }
            if i.consume_key(ctrl_shift, Key::X) {
                actions.push(Action::PurgeUnused);
            }
            if i.consume_key(ctrl_shift, Key::T) {
                actions.push(Action::PurgeTimers);
            }
            if i.consume_key(Modifiers::CTRL, Key::F) {
                actions.push(Action::Find);
            }
            if i.consume_key(Modifiers::NONE, Key::F5) {
                actions.push(Action::Refresh);
            }
            if i.consume_key(Modifiers::NONE, Key::F2) {
                actions.push(Action::Settings);
            }
            if i.consume_key(Modifiers::NONE, Key::F1) {
                actions.push(Action::About);
            }
            if typing {
                return;
            }
            if i.consume_key(Modifiers::NONE, Key::Delete) {
                actions.push(Action::Delete);
            }
            if i.consume_key(Modifiers::NONE, Key::Enter) {
                actions.push(Action::Open);
            }
            if i.consume_key(Modifiers::NONE, Key::Space) {
                actions.push(Action::Toggle);
            }
            if i.consume_key(Modifiers::NONE, Key::ArrowUp) {
                actions.push(Action::Move(-1));
            }
            if i.consume_key(Modifiers::NONE, Key::ArrowDown) {
                actions.push(Action::Move(1));
            }
            if i.consume_key(Modifiers::CTRL, Key::E) {
                actions.push(Action::Explore);
            }
            if i.events.iter().any(|e| matches!(e, Event::Copy)) {
                actions.push(Action::Copy);
            }
        });
        if self.dialog.is_some() {
            actions.retain(|a| matches!(a, Action::Find));
        }
        let selected = self.selected[self.tab.index()];
        for action in actions {
            match action {
                Action::Find => ctx.memory_mut(|m| m.request_focus(Id::new(FIND_ID))),
                Action::Refresh => self.refresh(),
                Action::Settings => self.dialog = Some(Dialog::Settings),
                Action::About => self.dialog = Some(Dialog::About),
                Action::NextTab | Action::PrevTab => {
                    let step = if matches!(action, Action::NextTab) { 1 } else { Tab::ALL.len() - 1 };
                    self.switch_tab(Tab::ALL[(self.tab.index() + step) % Tab::ALL.len()]);
                }
                Action::PurgeUnused => self.purge_unused(),
                Action::PurgeTimers => self.purge_timers(),
                Action::Delete => selected.into_iter().for_each(|id| self.delete(id)),
                Action::Open => selected.into_iter().for_each(|id| self.open(id)),
                Action::Toggle => selected.into_iter().for_each(|id| self.toggle(id)),
                Action::Explore => selected.into_iter().for_each(|id| self.explore(id)),
                Action::Copy => {
                    if let Some(text) = selected.and_then(|id| self.copy_text(id)) {
                        ctx.copy_text(text);
                    }
                }
                Action::Move(step) => self.move_selection(step),
            }
        }
    }

    fn move_selection(&mut self, step: i32) {
        let rows: Vec<(usize, usize)> = self
            .lines
            .iter()
            .enumerate()
            .filter_map(|(line, l)| match l {
                Line::Row(r) => Some((line, r.id)),
                Line::Group { .. } => None,
            })
            .collect();
        if rows.is_empty() {
            return;
        }
        let current = self.selected[self.tab.index()].and_then(|id| rows.iter().position(|(_, r)| *r == id));
        let next = match current {
            Some(pos) => (pos as i32 + step).clamp(0, rows.len() as i32 - 1) as usize,
            None => 0,
        };
        self.selected[self.tab.index()] = Some(rows[next].1);
        self.scroll_to = Some(rows[next].0);
    }

    // ---- panels --------------------------------------------------------

    fn menu_bar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("menu")
            .frame(egui::Frame::NONE.fill(theme::CHROME).inner_margin(Margin::symmetric(6, 2)))
            .show_separator_line(false)
            .show(ctx, |ui| {
                egui::menu::bar(ui, |ui| {
                    ui.spacing_mut().button_padding = vec2(8.0, 3.0);
                    ui.menu_button("File", |ui| {
                        if ui.button("Add app\u{2026}").clicked() {
                            ui.close_menu();
                            self.add_app();
                        }
                        if ui.add(egui::Button::new("Settings\u{2026}").shortcut_text("F2")).clicked() {
                            ui.close_menu();
                            self.dialog = Some(Dialog::Settings);
                        }
                        ui.separator();
                        if ui.button("Exit").clicked() {
                            ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                        }
                    });
                    ui.menu_button("Edit", |ui| {
                        if ui.add(egui::Button::new("Find\u{2026}").shortcut_text("Ctrl+F")).clicked() {
                            ui.close_menu();
                            ui.ctx().memory_mut(|m| m.request_focus(Id::new(FIND_ID)));
                        }
                        if ui.add(egui::Button::new("Refresh").shortcut_text("F5")).clicked() {
                            ui.close_menu();
                            self.refresh();
                        }
                        ui.separator();
                        if ui.add(egui::Button::new("Purge unused apps").shortcut_text("Ctrl+Shift+X")).clicked() {
                            ui.close_menu();
                            self.purge_unused();
                        }
                        if ui.add(egui::Button::new("Purge timers").shortcut_text("Ctrl+Shift+T")).clicked() {
                            ui.close_menu();
                            self.purge_timers();
                        }
                    });
                    ui.menu_button("View", |ui| {
                        let s = &mut self.profile.settings;
                        let mut save = false;
                        if ui.checkbox(&mut s.always_on_top, "Always on top").changed() {
                            let level = if s.always_on_top {
                                egui::WindowLevel::AlwaysOnTop
                            } else {
                                egui::WindowLevel::Normal
                            };
                            ui.ctx().send_viewport_cmd(egui::ViewportCommand::WindowLevel(level));
                            save = true;
                        }
                        save |= ui.checkbox(&mut s.show_filenames_only, "Show filenames only").changed();
                        if save {
                            self.save();
                            self.dirty = true;
                        }
                    });
                    ui.menu_button("Settings", |ui| {
                        let s = &mut self.profile.settings;
                        let mut changed = false;
                        changed |= ui.checkbox(&mut s.allow_loopback, "Allow loopback connections").changed();
                        changed |= ui.checkbox(&mut s.allow_ipv6, "Allow IPv6 neighbor discovery").changed();
                        changed |= ui.checkbox(&mut s.allow_lan, "Allow local network (LAN)").changed();
                        changed |= ui
                            .checkbox(&mut s.user_allows_override_blocklist, "User rules take priority over blocklist")
                            .changed();
                        ui.separator();
                        if ui.button("All settings\u{2026}").clicked() {
                            ui.close_menu();
                            self.dialog = Some(Dialog::Settings);
                        }
                        if changed {
                            self.changed();
                        }
                    });
                    ui.menu_button("Blocklist", |ui| {
                        for group in BlocklistGroup::all() {
                            ui.menu_button(group.label(), |ui| {
                                let mut state = self.profile.settings.blocklist(group);
                                for option in BlocklistState::all() {
                                    ui.radio_value(&mut state, option, option.label());
                                }
                                if state != self.profile.settings.blocklist(group) {
                                    self.profile.settings.set_blocklist(group, state);
                                    self.profile.apply_blocklist(group);
                                    self.changed();
                                }
                            });
                        }
                    });
                    ui.menu_button("Help", |ui| {
                        if ui.button("Website").clicked() {
                            ui.close_menu();
                            shell::open("https://github.com/NitroDiesel/simplewall");
                        }
                        if ui.add(egui::Button::new("About").shortcut_text("F1")).clicked() {
                            ui.close_menu();
                            self.dialog = Some(Dialog::About);
                        }
                    });
                });
            });
    }

    fn toolbar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("toolbar")
            .frame(egui::Frame::NONE.fill(theme::CHROME).inner_margin(Margin::symmetric(6, 4)))
            .show_separator_line(false)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 2.0;
                    let accent = self.accent;
                    let (icon, label) = if self.filters_on {
                        (&self.icons.shield_off, "Disable filtering")
                    } else {
                        (&self.icons.shield_on, "Enable filtering")
                    };
                    let icon = icon.clone();
                    if tool_button(ui, &icon, Some(label), "Enable or disable filtering", false, accent).clicked() {
                        self.dialog = Some(Dialog::Confirm(!self.filters_on));
                    }
                    tool_separator(ui);
                    let plus = self.icons.plus.clone();
                    if tool_button(ui, &plus, None, "Create rule", false, accent).clicked() {
                        let apps = self.selected_app_path().into_iter().collect();
                        self.dialog = Some(Dialog::Rule(RuleDraft::new(apps)));
                    }
                    tool_separator(ui);
                    let note = self.icons.note.clone();
                    let log_file = self.profile.settings.log_to_file;
                    if tool_button(ui, &note, None, "Log to file", log_file, accent).clicked() {
                        self.profile.settings.log_to_file = !log_file;
                        self.save();
                    }
                    let eye = self.icons.eye.clone();
                    let log_ui = self.profile.settings.log_ui;
                    if tool_button(ui, &eye, None, "Log to UI (Packets log)", log_ui, accent).clicked() {
                        self.set_log_ui(!log_ui);
                    }
                    tool_separator(ui);
                    let refresh = self.icons.refresh.clone();
                    if tool_button(ui, &refresh, None, "Refresh (F5)", false, accent).clicked() {
                        self.refresh();
                    }
                    let settings = self.icons.settings.clone();
                    if tool_button(ui, &settings, None, "Settings (F2)", false, accent).clicked() {
                        self.dialog = Some(Dialog::Settings);
                    }
                    tool_separator(ui);
                    let show = self.icons.log_show.clone();
                    if tool_button(ui, &show, None, "Show log", false, accent).clicked() {
                        let path = log::log_path();
                        if path.exists() {
                            shell::open(&path.to_string_lossy());
                        } else {
                            self.notify("The log file is empty.", false);
                        }
                    }
                    let clear = self.icons.log_clear.clone();
                    if tool_button(ui, &clear, None, "Clear log", false, accent).clicked() {
                        let _ = std::fs::remove_file(log::log_path());
                        self.packets_cleared_at = now_unix();
                        self.packets.clear();
                        self.dirty = true;
                        self.notify("Log cleared.", false);
                    }

                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        self.search_box(ui);
                    });
                });
            });
    }

    fn set_log_ui(&mut self, on: bool) {
        self.profile.settings.log_ui = on;
        self.save();
        if let Err(err) = wfp::set_packet_log(on) {
            self.notify(err, true);
        }
        if self.tab == Tab::Packets {
            self.load_packets();
        }
    }

    fn selected_app_path(&self) -> Option<String> {
        self.tab.app_kind()?;
        let id = self.selected[self.tab.index()]?;
        self.profile.apps.get(id).map(|a| a.path.clone())
    }

    fn search_box(&mut self, ui: &mut Ui) {
        let edit = egui::TextEdit::singleline(&mut self.query)
            .id(Id::new(FIND_ID))
            .hint_text("Find... (Ctrl+F)")
            .desired_width(260.0)
            .margin(Margin { left: 10, right: 30, top: 6, bottom: 6 });
        let response = ui.add(edit);
        let center = pos2(response.rect.right() - 16.0, response.rect.center().y);
        if self.query.is_empty() {
            // Magnifier, drawn so it takes the text color.
            let color = if response.has_focus() { theme::TEXT } else { theme::TEXT_MUTED };
            let stroke = Stroke::new(1.5_f32, color);
            let lens = center + vec2(-1.5, -1.5);
            ui.painter().circle_stroke(lens, 4.5, stroke);
            ui.painter().line_segment([lens + vec2(3.3, 3.3), lens + vec2(7.0, 7.0)], stroke);
        } else {
            // The C build's clear button.
            let rect = Rect::from_center_size(center, vec2(20.0, 20.0));
            let clear = ui.interact(rect, Id::new("find_clear"), Sense::click());
            let hover = ui.ctx().animate_bool_with_time(clear.id, clear.hovered(), HOVER_FADE);
            if hover > 0.0 {
                ui.painter().rect_filled(rect, 4.0, Color32::from_white_alpha((16.0 * hover) as u8));
            }
            let icon = Rect::from_center_size(center, vec2(14.0, 14.0));
            let uv = Rect::from_min_max(pos2(0.0, 0.0), pos2(1.0, 1.0));
            ui.painter().image(self.icons.search.id(), icon, uv, Color32::WHITE);
            if clear.on_hover_text("Clear").clicked() {
                self.query.clear();
                self.dirty = true;
            }
        }
        if response.has_focus() && ui.input(|i| i.key_pressed(Key::Escape)) {
            self.query.clear();
            self.dirty = true;
        }
        if response.changed() {
            self.dirty = true;
        }
    }

    fn tabs(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("tabs")
            .frame(egui::Frame::NONE.fill(theme::CHROME).inner_margin(Margin { left: 6, right: 6, top: 2, bottom: 0 }))
            .show_separator_line(false)
            .show(ctx, |ui| {
                let mut active = None;
                let mut clicked = None;
                let bar = ui
                    .horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 2.0;
                        for tab in Tab::ALL {
                            let selected = tab == self.tab;
                            let font = FontId::proportional(13.0);
                            let galley = ui.painter().layout_no_wrap(tab.label().into(), font, theme::TEXT);
                            let (rect, response) =
                                ui.allocate_exact_size(vec2(galley.size().x + 26.0, 34.0), Sense::click());
                            let hover = ui.ctx().animate_bool_with_time(response.id, response.hovered(), HOVER_FADE);
                            if hover > 0.0 && !selected {
                                let fill = Color32::from_white_alpha((10.0 * hover) as u8);
                                ui.painter().rect_filled(rect.shrink2(vec2(0.0, 4.0)), 4.0, fill);
                            }
                            let color = if selected {
                                theme::TEXT
                            } else {
                                lerp_color(theme::TEXT_MUTED, theme::TEXT, hover)
                            };
                            let pos = rect.center() - galley.size() / 2.0;
                            ui.painter().galley(pos, galley, color);
                            if selected {
                                active = Some(rect.shrink2(vec2(10.0, 0.0)).x_range());
                            }
                            if response.clicked() {
                                clicked = Some(tab);
                            }
                        }
                    })
                    .response
                    .rect;
                ui.painter().hline(
                    ui.max_rect().x_range(),
                    bar.bottom() - 0.5,
                    Stroke::new(1.0_f32, theme::BORDER),
                );
                if let Some(target) = active {
                    let drawn = self.slide_underline(ui.ctx(), target);
                    let rect = Rect::from_x_y_ranges(drawn, bar.bottom() - 3.0..=bar.bottom());
                    ui.painter().rect_filled(rect, CornerRadius::same(2), self.accent);
                }
                if let Some(tab) = clicked {
                    self.switch_tab(tab);
                }
            });
    }

    /// Ease-out slide from the last drawn position; repaints only while moving.
    fn slide_underline(&mut self, ctx: &egui::Context, target: Rangef) -> Rangef {
        let now = ctx.input(|i| i.time);
        let tab = self.tab;
        let line = self.underline.get_or_insert(Underline { tab, drawn: target, from: target, start: now - TAB_SLIDE });
        if line.tab != tab {
            line.tab = tab;
            line.from = line.drawn;
            line.start = now;
        }
        let t = ((now - line.start) / TAB_SLIDE).clamp(0.0, 1.0) as f32;
        let e = easing::cubic_out(t);
        let drawn = Rangef::new(
            line.from.min + (target.min - line.from.min) * e,
            line.from.max + (target.max - line.from.max) * e,
        );
        line.drawn = drawn;
        if t < 1.0 {
            ctx.request_repaint();
        }
        drawn
    }

    fn status_bar(&mut self, ctx: &egui::Context) {
        let (text, color, dot) = self.status_text();
        egui::TopBottomPanel::bottom("status")
            .exact_height(26.0)
            .frame(egui::Frame::NONE.fill(theme::CHROME).inner_margin(Margin::symmetric(10, 0)))
            .show_separator_line(false)
            .show(ctx, |ui| {
                let full = ui.max_rect();
                ui.painter().hline(
                    full.x_range().expand(10.0),
                    full.top() + 0.5,
                    Stroke::new(1.0_f32, theme::BORDER),
                );
                let part = 170.0;
                let first = (full.width() - part * 2.0).max(220.0);
                let painter = ui.painter();
                let y = full.center().y;
                painter.circle_filled(pos2(full.left() + 4.0, y), 3.5, dot);
                let galley = painter.layout_no_wrap(text, FontId::proportional(12.5), color);
                painter.galley(pos2(full.left() + 16.0, y - galley.size().y / 2.0), galley, color);
                let parts = [
                    format!("Unused apps: {}", self.unused),
                    format!("Apps with timer: {}", self.timers),
                ];
                for (i, label) in parts.into_iter().enumerate() {
                    let x = full.left() + first + part * i as f32;
                    painter.vline(x, full.top() + 6.0..=full.bottom() - 6.0, Stroke::new(1.0_f32, theme::BORDER));
                    let galley = painter.layout_no_wrap(label, FontId::proportional(12.5), theme::TEXT_MUTED);
                    painter.galley(pos2(x + 10.0, y - galley.size().y / 2.0), galley, theme::TEXT_MUTED);
                }
            });
    }

    fn status_text(&mut self) -> (String, Color32, Color32) {
        if let Some(notice) = &self.notice {
            if Instant::now() >= notice.until {
                self.notice = None;
            }
        }
        if self.worker.busy() {
            return ("Applying filters\u{2026}".into(), theme::TEXT, self.accent);
        }
        if let Some(notice) = &self.notice {
            let color = if notice.error { theme::DANGER } else { theme::TEXT };
            return (notice.text.clone(), color, if notice.error { theme::DANGER } else { self.accent });
        }
        if self.filters_on {
            let text = if self.profile.settings.filters_temporary {
                "Filters are enabled until reboot."
            } else {
                "Filters are enabled."
            };
            (text.into(), theme::TEXT, Color32::from_rgb(0x6C, 0xCB, 0x5F))
        } else {
            ("Filters are disabled!".into(), theme::TEXT, theme::DANGER)
        }
    }

    fn list(&mut self, ctx: &egui::Context) {
        let index = self.tab.index();
        let empty = self.empty_text();
        let output = egui::CentralPanel::default()
            .frame(egui::Frame::NONE.fill(theme::SURFACE))
            .show(ctx, |ui| {
                let mut art = list::Art {
                    icons: &self.icons,
                    files: &mut self.files,
                    accent: self.accent,
                };
                List {
                    id: Id::new(("list", index)),
                    columns: self.tab.columns(),
                    lines: &self.lines,
                    sort: self.sorts[index],
                    selected: self.selected[index],
                    scroll_to: self.scroll_to.take(),
                    empty: &empty,
                }
                .show(ui, &mut art)
            })
            .inner;

        if let Some(column) = output.sort {
            let sort = &mut self.sorts[index];
            if sort.column == column {
                sort.descending = !sort.descending;
            } else {
                *sort = Sort { column, descending: false };
            }
            self.dirty = true;
        }
        if let Some(group) = output.group {
            let set = &mut self.collapsed[index];
            if !set.remove(&group) {
                set.insert(group);
            }
            self.dirty = true;
        }
        if let Some(id) = output.clicked {
            self.selected[index] = Some(id);
        }
        if let Some(id) = output.toggled {
            self.selected[index] = Some(id);
            self.toggle(id);
        }
        if let Some(id) = output.activated {
            self.open(id);
        }
        if output.pending_icons {
            ctx.request_repaint();
        }
        for (id, response) in output.rows {
            response.context_menu(|ui| self.context_menu(ui, id));
        }
    }

    fn empty_text(&self) -> String {
        if self.tab == Tab::Packets {
            if let Some(state) = &self.packets_state {
                return state.clone();
            }
        }
        if !self.query.trim().is_empty() {
            return format!("Nothing matches \u{201C}{}\u{201D}.", self.query.trim());
        }
        match self.tab {
            Tab::Packets => "No dropped packets yet.".into(),
            Tab::Connections => "No active connections.".into(),
            Tab::User => "No user rules. Use + in the toolbar to create one.".into(),
            _ => "Nothing here.".into(),
        }
    }

    fn context_menu(&mut self, ui: &mut Ui, id: usize) {
        self.selected[self.tab.index()] = Some(id);
        if self.tab.app_kind().is_some() {
            let Some(app) = self.profile.apps.get(id).cloned() else {
                return;
            };
            let label = if app.enabled { "Block network access" } else { "Allow network access" };
            if ui.add(egui::Button::new(label).shortcut_text("Space")).clicked() {
                ui.close_menu();
                self.toggle(id);
            }
            ui.menu_button("Timer", |ui| {
                for (seconds, label) in TIMERS {
                    if ui.button(label).clicked() {
                        ui.close_menu();
                        self.set_timer(id, seconds);
                    }
                }
                if app.has_timer() {
                    ui.separator();
                    if ui.button("Disable timer").clicked() {
                        ui.close_menu();
                        if let Some(app) = self.profile.apps.get_mut(id) {
                            app.timer_until = 0;
                        }
                        self.changed();
                    }
                }
            });
            ui.separator();
            if ui.button("Create rule for this app\u{2026}").clicked() {
                ui.close_menu();
                self.dialog = Some(Dialog::Rule(RuleDraft::new(vec![app.path.clone()])));
            }
            if ui.add(egui::Button::new("Properties\u{2026}").shortcut_text("Enter")).clicked() {
                ui.close_menu();
                self.open(id);
            }
            if ui.button(if app.pinned { "Unpin" } else { "Pin" }).clicked() {
                ui.close_menu();
                if let Some(app) = self.profile.apps.get_mut(id) {
                    app.pinned = !app.pinned;
                }
                self.changed();
            }
            if matches!(app.kind, AppKind::Regular | AppKind::Service)
                && ui.add(egui::Button::new("Open file location").shortcut_text("Ctrl+E")).clicked()
            {
                ui.close_menu();
                self.explore(id);
            }
            ui.separator();
            if ui.add(egui::Button::new("Copy").shortcut_text("Ctrl+C")).clicked() {
                ui.close_menu();
                ui.ctx().copy_text(app.path.clone());
            }
            if app.kind != AppKind::System && ui.add(egui::Button::new("Delete").shortcut_text("Del")).clicked() {
                ui.close_menu();
                self.delete(id);
            }
        } else if self.tab.rule_origin().is_some() {
            let Some(rule) = self.profile.rules.get(id).cloned() else {
                return;
            };
            let label = if rule.enabled { "Disable rule" } else { "Enable rule" };
            if ui.add(egui::Button::new(label).shortcut_text("Space")).clicked() {
                ui.close_menu();
                self.toggle(id);
            }
            let edit = if rule.origin == RuleOrigin::User { "Edit\u{2026}" } else { "View\u{2026}" };
            if ui.add(egui::Button::new(edit).shortcut_text("Enter")).clicked() {
                ui.close_menu();
                self.open(id);
            }
            ui.separator();
            if ui.add(egui::Button::new("Copy").shortcut_text("Ctrl+C")).clicked() {
                ui.close_menu();
                if let Some(text) = self.copy_text(id) {
                    ui.ctx().copy_text(text);
                }
            }
            if rule.origin == RuleOrigin::User && ui.add(egui::Button::new("Delete").shortcut_text("Del")).clicked() {
                ui.close_menu();
                self.delete(id);
            }
        } else if ui.add(egui::Button::new("Copy").shortcut_text("Ctrl+C")).clicked() {
            ui.close_menu();
            if let Some(text) = self.copy_text(id) {
                ui.ctx().copy_text(text);
            }
        }
    }

    fn dialogs(&mut self, ctx: &egui::Context) {
        let Some(mut dialog) = self.dialog.take() else {
            return;
        };
        let effect = match &mut dialog {
            Dialog::Rule(draft) => dialogs::rule_editor(ctx, draft, &self.profile, self.accent),
            Dialog::App(index) => dialogs::app_properties(ctx, *index, &mut self.profile),
            Dialog::Settings => {
                let before = self.profile.settings.clone();
                let effect = dialogs::settings(ctx, &mut self.profile);
                for group in BlocklistGroup::all() {
                    if before.blocklist(group) != self.profile.settings.blocklist(group) {
                        self.profile.apply_blocklist(group);
                    }
                }
                if before.always_on_top != self.profile.settings.always_on_top {
                    let level = if self.profile.settings.always_on_top {
                        egui::WindowLevel::AlwaysOnTop
                    } else {
                        egui::WindowLevel::Normal
                    };
                    ctx.send_viewport_cmd(egui::ViewportCommand::WindowLevel(level));
                }
                effect
            }
            Dialog::About => dialogs::about(ctx, &self.icons.logo),
            Dialog::Confirm(enable) => dialogs::confirm(ctx, *enable, self.accent),
        };
        let keep = match effect {
            Effect::None => true,
            Effect::Close => false,
            Effect::Changed => {
                self.changed();
                true
            }
            Effect::SaveRule(rule, index) => {
                match index {
                    Some(i) if i < self.profile.rules.len() => self.profile.rules[i] = *rule,
                    _ => {
                        self.profile.rules.push(*rule);
                        let id = self.profile.rules.len() - 1;
                        self.switch_tab(Tab::User);
                        self.selected[Tab::User.index()] = Some(id);
                    }
                }
                self.changed();
                false
            }
            Effect::SetFilters(enable, temporary) => {
                self.set_filters(enable, temporary);
                false
            }
        };
        if keep && ctx.input(|i| i.key_pressed(Key::Escape)) && !matches!(dialog, Dialog::Confirm(_)) {
            return;
        }
        if keep {
            self.dialog = Some(dialog);
        }
    }
}

impl eframe::App for SimplewallApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_worker();
        self.tick_timers(ctx);
        self.shortcuts(ctx);
        if self.dirty {
            self.rebuild();
        }
        if let Some(notice) = &self.notice {
            ctx.request_repaint_after(notice.until.saturating_duration_since(Instant::now()));
        }
        self.menu_bar(ctx);
        self.toolbar(ctx);
        self.tabs(ctx);
        self.status_bar(ctx);
        self.list(ctx);
        self.dialogs(ctx);
        if self.dirty {
            ctx.request_repaint();
        }
    }
}

/// Toolbar button: 20px icon, optional label, hover fade, 0.96 press scale.
fn tool_button(ui: &mut Ui, icon: &TextureHandle, label: Option<&str>, tip: &str, checked: bool, accent: Color32) -> Response {
    let font = FontId::proportional(13.0);
    let galley = label.map(|l| ui.painter().layout_no_wrap(l.into(), font, theme::TEXT));
    let width = 10.0 + 20.0 + galley.as_ref().map_or(0.0, |g| 8.0 + g.size().x) + 10.0;
    let (rect, response) = ui.allocate_exact_size(vec2(width, 34.0), Sense::click());
    let hover = ui.ctx().animate_bool_with_time(response.id, response.hovered(), HOVER_FADE);
    let scale = if response.is_pointer_button_down_on() { 0.96 } else { 1.0 };
    let body = Rect::from_center_size(rect.center(), rect.size() * scale);
    let painter = ui.painter();
    if checked {
        painter.rect_filled(body, 5.0, accent.gamma_multiply(0.22));
        painter.rect_stroke(body, 5.0, Stroke::new(1.0_f32, accent.gamma_multiply(0.55)), egui::StrokeKind::Inside);
    }
    if hover > 0.0 {
        painter.rect_filled(body, 5.0, Color32::from_white_alpha((14.0 * hover) as u8));
    }
    let icon_size = 20.0 * scale;
    let icon_left = body.left() + 10.0 * scale;
    let icon_rect = Rect::from_min_size(pos2(icon_left, body.center().y - icon_size / 2.0), vec2(icon_size, icon_size));
    painter.image(icon.id(), icon_rect, Rect::from_min_max(pos2(0.0, 0.0), pos2(1.0, 1.0)), Color32::WHITE);
    if let Some(galley) = galley {
        let pos = pos2(icon_rect.right() + 8.0, body.center().y - galley.size().y / 2.0);
        painter.galley(pos, galley, theme::TEXT);
    }
    response.on_hover_text(tip)
}

fn tool_separator(ui: &mut Ui) {
    let (rect, _) = ui.allocate_exact_size(vec2(11.0, 34.0), Sense::hover());
    ui.painter().vline(rect.center().x, rect.top() + 8.0..=rect.bottom() - 8.0, Stroke::new(1.0_f32, theme::BORDER));
}

fn lerp_color(a: Color32, b: Color32, t: f32) -> Color32 {
    let mix = |x: u8, y: u8| (x as f32 + (y as f32 - x as f32) * t).round() as u8;
    Color32::from_rgb(mix(a.r(), b.r()), mix(a.g(), b.g()), mix(a.b(), b.b()))
}
