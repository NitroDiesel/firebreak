//! Main window with the C build's layout: menu bar, toolbar with the search box
//! on the right, eight tabs, a grouped report list, and a three-part status bar.
//! Filter installs run on a worker thread so the list never stalls.

mod dialogs;
mod inspect;
mod list;
mod monitor;
mod notify;
mod shell;
mod theme;
mod view;

use crate::i18n::t;
use std::collections::HashSet;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::{Duration, Instant};

use eframe::egui::{
    self, emath::easing, pos2, vec2, Align, Color32, CornerRadius, Event, Id, Key, Layout,
    Margin, Modifiers, Rangef, Rect, Response, Sense, Stroke, TextureHandle, Ui,
};

use crate::apps;
use crate::log::{self, Endpoint};
use crate::model::{now_unix, protocol_label, AppItem, AppKind, BlocklistGroup, BlocklistState, Profile, RuleOrigin};
use crate::profile;
use crate::netevents::{self, Packet};
use crate::wfp;

use dialogs::{Ask, Dialog, Effect, RuleDraft, TIMERS};
use list::{FileIcons, Line, List, Sort};
use crate::tray::{Tray, TrayCommand, TrayState};
use theme::Icons;
use view::Tab;

const FIND_ID: &str = "find";
const NOTICE_SECONDS: u64 = 6;
const TAB_SLIDE: f64 = 0.2;
const HOVER_FADE: f32 = 0.12;
/// Right padding inside the search box, where the magnifier or clear button sits.
const SEARCH_ICON_GUTTER: f32 = 32.0;

enum Job {
    Install { seq: u64, profile: Box<Profile>, temporary: bool },
    Uninstall { seq: u64 },
}

enum Reply {
    Filters { seq: u64, enabled: bool, result: Result<String, String> },
    Packets(Result<Vec<Packet>, String>),
    /// A newer version, or none; `manual` when asked from the Help menu.
    Update { result: Result<Option<String>, String>, manual: bool },
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
    ShowLog,
    ClearLog,
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
    /// Measured column widths for Autosize columns, refreshed after each rebuild.
    auto_widths: Vec<f32>,
    widths_stale: bool,
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
    /// Tab was pressed since the last click, so keyboard focus is drawn.
    keyboard: bool,
    /// Set once the close confirmation was accepted.
    closing: bool,
    tray: Option<Tray>,
    tray_rx: Receiver<TrayCommand>,
    /// Last state sent to the tray, so it is only refreshed on change.
    tray_state: TrayState,
    /// Minimized with the taskbar button removed.
    in_tray: bool,
    /// Go to the tray on the first frame (`-minimized` or t("Start minimized")).
    start_minimized: bool,
    /// Task Scheduler state, read when Settings first opens.
    startup: Option<dialogs::Startup>,
    /// Always-on-top state last sent to the window.
    on_top: bool,
    /// The theme in use.
    dark: bool,
    /// Last size of the restored window, saved on exit.
    window_size: Option<egui::Vec2>,
    /// Signature and hash checks.
    inspector: inspect::Inspector,
    monitor: monitor::Monitor,
    resolver: monitor::Resolver,
    /// Lowercase paths of apps with an established connection.
    connected: HashSet<String>,
    /// Allowed apps waiting for a fresh hash to compare against later.
    hash_baseline: HashSet<String>,
    last_hash_sweep: Instant,
    /// Running elevated; needed for event subscriptions.
    admin: bool,
    /// Live dropped-connection events, while notifications or a log need them.
    events: Option<netevents::Subscription>,
    events_tx: Sender<Packet>,
    events_rx: Receiver<Packet>,
    /// Subscribing failed; do not retry every frame.
    events_failed: bool,
    /// Last event-collection state set on the engine.
    collecting: Option<bool>,
    /// A newer release found by the update check.
    update_available: Option<String>,
    /// Last app monitor scan.
    last_app_scan: Instant,
    /// Pending notifications, one per app.
    alerts: Vec<Packet>,
    alert_index: usize,
}

impl SimplewallApp {
    pub fn new(cc: &eframe::CreationContext<'_>, minimized: bool) -> Self {
        let ctx = &cc.egui_ctx;
        let accent = theme::accent();
        let first_run = profile::is_first_run();
        let mut profile = profile::load();
        // Bring over the C build's apps and rules the first time this port runs.
        let mut first_notice = None;
        if let Some(path) = first_run.then(profile::original_profile_path).flatten() {
            if let Ok(found) = std::fs::read(&path).map_err(|e| e.to_string()).and_then(|b| profile::import(&mut profile, &b)) {
                first_notice = Some(format!(
                    "Imported {} apps and {} user rules from {}.",
                    found.apps,
                    found.rules,
                    path.display()
                ));
            }
        }
        profile.apps = apps::merge(&profile.apps, apps::enumerate());
        let dark = match profile.settings.theme {
            1 => true,
            2 => false,
            _ => theme::system_is_dark(),
        };
        crate::i18n::set_language(&profile.settings.language);
        let s = &profile.settings;
        theme::apply(ctx, accent, dark, s.theme == 0, &s.language, &s.font, s.font_size);
        let (width, height) = (profile.settings.window_width, profile.settings.window_height);
        if width >= 640 && height >= 400 {
            ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(vec2(width as f32, height as f32)));
        }
        let filters_on = wfp::filters_installed().unwrap_or(false);
        let sort = Sort { column: 0, descending: false };
        let start_minimized = minimized || profile.settings.start_minimized;
        let (network_monitor, show_waiting) =
            (profile.settings.network_monitor, profile.settings.show_wait_connections);
        let (tray_tx, tray_rx) = channel();
        let (events_tx, events_rx) = channel();
        let tray_state = tray_state_of(&profile, filters_on, false);
        let tray = Tray::spawn(ctx.clone(), tray_tx, tray_state.clone());
        if let (Some(tray), Some(hwnd)) = (&tray, main_hwnd(cc)) {
            tray.set_main_window(hwnd);
        }
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
            auto_widths: Vec::new(),
            widths_stale: true,
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
            keyboard: false,
            closing: false,
            tray,
            tray_rx,
            tray_state,
            in_tray: false,
            start_minimized,
            startup: None,
            on_top: false,
            dark,
            window_size: None,
            inspector: inspect::Inspector::spawn(ctx.clone()),
            monitor: monitor::Monitor::spawn(ctx.clone(), network_monitor, show_waiting),
            resolver: monitor::Resolver::spawn(ctx.clone()),
            connected: HashSet::new(),
            hash_baseline: HashSet::new(),
            last_hash_sweep: Instant::now(),
            admin: wfp::is_admin(),
            events: None,
            events_tx,
            events_rx,
            events_failed: false,
            collecting: None,
            update_available: None,
            last_app_scan: Instant::now(),
            alerts: Vec::new(),
            alert_index: 0,
        };
        // Packets log sorts newest first, as in the C build.
        app.sorts[Tab::Packets.index()] = Sort { column: 1, descending: true };
        // Last tab and sort order (CurrentTab, SortColumn, SortIsDescending).
        for (sort, saved) in app.sorts.iter_mut().zip(app.profile.settings.sorts.split(',')) {
            if let Some((column, desc)) = saved.split_once(':') {
                if let Ok(column) = column.parse() {
                    *sort = Sort { column, descending: desc == "1" };
                }
            }
        }
        if let Some(tab) = Tab::ALL.get(app.profile.settings.current_tab as usize) {
            app.tab = *tab;
        }
        if app.tab == Tab::Packets {
            app.load_packets();
        }
        app.check_for_updates(false);
        app.save();
        if let Some(text) = first_notice {
            app.notify(text, false);
        }
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

    /// A message in the status bar. Errors stay until clicked; others fade after a few seconds.
    fn notify(&mut self, text: impl Into<String>, error: bool) {
        let shown = if error { Duration::from_secs(24 * 60 * 60) } else { Duration::from_secs(NOTICE_SECONDS) };
        self.notice = Some(Notice {
            text: text.into(),
            error,
            until: Instant::now() + shown,
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
                        }
                        Err(err) => {
                            self.filters_on = wfp::filters_installed().unwrap_or(self.filters_on);
                            let what = if enabled { t("Enable filtering") } else { t("Disable filtering") };
                            self.notify(format!("{what} failed: {err}. Select {what} to try again."), true);
                        }
                    }
                }
                Reply::Update { result, manual } => match result {
                    Ok(Some(version)) => {
                        self.notify(format!("simplewall {version} is available: Help > Download update."), false);
                        self.update_available = Some(version);
                    }
                    Ok(None) if manual => self.notify("You have the latest version.", false),
                    Err(err) if manual => self.notify(err, true),
                    _ => {}
                },
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
        let s = &self.profile.settings;
        if s.check_signatures {
            for app in self.profile.apps.iter().filter(|a| a.kind == AppKind::Regular) {
                self.inspector.want_signature(&app.path, s.check_revocation);
            }
        }
        let signers = self.inspector.signers();
        if s.resolve_hostnames && self.tab == Tab::Connections {
            for ip in self.connections.iter().filter_map(|c| c.remote_ip) {
                self.resolver.ask(ip);
            }
        }
        let hosts = if s.resolve_hostnames { self.resolver.hosts() } else { Default::default() };
        let source = view::Source {
            profile: &self.profile,
            connections: &self.connections,
            packets: &self.packets,
            query: &self.query,
            sort: self.sorts[index],
            collapsed: &self.collapsed[index],
            signers: &signers,
            connected: &self.connected,
            hosts: &hosts,
            traffic: self.admin,
        };
        self.lines = view::build(self.tab, &source);
        self.widths_stale = true;
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
            Tab::Connections => self.connections = log::connections(self.profile.settings.show_wait_connections, false),
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
            let _ = tx.send(Reply::Packets(crate::netevents::history(2000)));
        });
    }

    fn refresh(&mut self) {
        self.profile.apps = apps::merge(&self.profile.apps, apps::enumerate());
        match self.tab {
            Tab::Connections => self.connections = log::connections(self.profile.settings.show_wait_connections, false),
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

    fn ask_purge_unused(&mut self) {
        let count = self.profile.apps.iter().filter(|a| self.profile.app_is_unused(a)).count();
        if count == 0 {
            self.notify("There are no unused apps.", false);
        } else {
            self.dialog = Some(Dialog::Confirm(Ask::PurgeUnused(count)));
        }
    }

    fn clear_log(&mut self) {
        let _ = std::fs::remove_file(log::log_path());
        self.packets_cleared_at = now_unix();
        self.packets.clear();
        self.dirty = true;
        self.notify("Log cleared.", false);
    }

    /// Timers only count down while the window is open, so closing ends them
    /// instead of leaving the apps allowed with nothing to block them later.
    fn end_timers_and_close(&mut self, ctx: &egui::Context) {
        for app in self.profile.apps.iter_mut().filter(|a| a.has_timer()) {
            app.timer_until = 0;
            app.enabled = false;
        }
        self.save();
        if self.filters_on {
            if let Err(err) = wfp::install(&self.profile, self.profile.settings.filters_temporary) {
                self.notify(err, true);
                return;
            }
        }
        self.closing = true;
        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
    }

    /// Subscribe to drop events while notifications or a packets log want them,
    /// and keep the engine collecting them (`_wfp_logsubscribe`).
    fn sync_events(&mut self, ctx: &egui::Context) {
        if !self.admin {
            return;
        }
        let s = &self.profile.settings;
        let want = s.notifications || s.log_ui || s.log_to_file;
        if self.collecting != Some(want) {
            let _ = wfp::set_event_collection(want);
            self.collecting = Some(want);
        }
        if !want {
            self.events = None;
            self.events_failed = false;
            return;
        }
        if self.events.is_some() || self.events_failed {
            return;
        }
        let tx = self.events_tx.clone();
        let waker = ctx.clone();
        match netevents::subscribe(move |packet| {
            if tx.send(packet).is_ok() {
                waker.request_repaint();
            }
        }) {
            Ok(subscription) => self.events = Some(subscription),
            Err(err) => {
                self.events_failed = true;
                self.notify(err, true);
            }
        }
    }

    /// Handle new drop events, like `_app_logthread`: collect unknown apps, fill
    /// the packets logs, and queue notifications for apps that are not allowed.
    fn drain_events(&mut self) {
        let packets: Vec<Packet> = self.events_rx.try_iter().take(5000).collect();
        if packets.is_empty() {
            return;
        }
        let now = now_unix();
        let mut added = false;
        let mut live = false;
        for packet in packets {
            let s = &self.profile.settings;
            // Port scans blocked by stealth mode would flood both logs (IsExcludeStealth).
            if s.log_exclude_stealth && packet.ours && wfp::is_stealth_filter(&packet.filter) {
                continue;
            }
            if s.log_to_file {
                self.write_log(&packet);
            }
            if !packet.ours {
                continue;
            }
            let index = match self.app_index(&packet) {
                Some(index) => index,
                None if packet.kind == AppKind::System => continue,
                None => {
                    self.profile.apps.push(app_from_packet(&packet));
                    added = true;
                    self.profile.apps.len() - 1
                }
            };
            let s = &self.profile.settings;
            if s.log_ui && packet.time > self.packets_cleared_at {
                self.packets.insert(0, packet.clone());
                self.packets.truncate(5000);
                live = true;
            }
            let (notify, timeout) = (s.notifications, s.notifications_timeout);
            let app = &mut self.profile.apps[index];
            if notify && packet.default_block && !app.silent && !app.enabled {
                if timeout == 0 || now.saturating_sub(app.last_notify) >= timeout {
                    app.last_notify = now;
                    self.push_alert(packet);
                }
            }
        }
        if added {
            self.save();
            self.dirty = true;
        }
        if live && self.tab == Tab::Packets {
            self.dirty = true;
        }
    }

    fn app_index(&self, packet: &Packet) -> Option<usize> {
        // Events name a file, a package SID, or System; never a service name.
        self.profile
            .apps
            .iter()
            .position(|app| app.kind != AppKind::Service && app.path.eq_ignore_ascii_case(&packet.path))
    }

    fn push_alert(&mut self, packet: Packet) {
        self.alerts.retain(|a| !a.path.eq_ignore_ascii_case(&packet.path));
        self.alerts.push(packet);
        let s = &self.profile.settings;
        if s.notifications_sound && !(s.notifications_fullscreen_silent && shell::fullscreen_app_in_front()) {
            shell::play_alert_sound();
        }
    }

    /// One CSV line per dropped connection, in the C build's column order
    /// (SZ_LOG_TITLE). The file starts over at the size limit.
    fn write_log(&self, packet: &Packet) {
        let path = log::log_path();
        let limit = self.profile.settings.log_size_limit_kb * 1024;
        if limit > 0 && std::fs::metadata(&path).is_ok_and(|m| m.len() >= limit) {
            let _ = std::fs::remove_file(&path);
        }
        if !path.exists() {
            log::append_file(
                &path,
                "Date,Username,Path,Address (Local),Port (Local),Address (Remote),Port (Remote),Protocol,Layer,Filter name,Filter ID,Direction,State",
            );
        }
        let quote = |s: &str| format!("\"{}\"", s.replace('"', "\"\""));
        let port = |p: u16| if p == 0 { String::new() } else { p.to_string() };
        let fields = [
            quote(&shell::format_time(packet.time)),
            quote(""),
            quote(&packet.path),
            quote(&packet.local_addr),
            quote(&port(packet.local_port)),
            quote(&packet.remote_addr),
            quote(&port(packet.remote_port)),
            quote(protocol_label(packet.protocol)),
            quote(if packet.inbound { "ALE receive/accept" } else { "ALE connect" }),
            quote(&packet.filter),
            quote(&format!("#{}", packet.filter_id)),
            quote(packet.direction()),
            quote("Blocked"),
        ];
        log::append_file(&path, &fields.join(","));
    }

    /// The notification window for the current alert.
    fn alerts_ui(&mut self, ctx: &egui::Context) {
        if self.alerts.is_empty() {
            return;
        }
        self.alert_index = self.alert_index.min(self.alerts.len() - 1);
        let packet = self.alerts[self.alert_index].clone();
        let Some(index) = self.app_index(&packet) else {
            self.alerts.remove(self.alert_index);
            return;
        };
        let app = self.profile.apps[index].clone();
        if app.enabled || app.silent {
            self.alerts.remove(self.alert_index);
            return;
        }
        let s = &self.profile.settings;
        let signature = (s.check_signatures && app.kind == AppKind::Regular).then(|| {
            self.inspector.want_signature(&app.path, s.check_revocation);
            self.inspector.signer(&app.path)
        });
        let host = match packet.remote_addr.parse() {
            Ok(ip) if s.resolve_hostnames => self.resolver.host(ip).flatten(),
            _ => None,
        };
        let alert = notify::Alert {
            packet: &packet,
            app: &app,
            position: self.alert_index,
            count: self.alerts.len(),
            accent: self.accent,
            signature: signature.flatten(),
            host,
        };
        let files = &mut self.files;
        let action = ctx.show_viewport_immediate(
            egui::ViewportId::from_hash_of("simplewall-alert"),
            notify::builder(ctx, alert.height()),
            |ctx, _| notify::show(ctx, &alert, files),
        );
        let done = |alerts: &mut Vec<Packet>| alerts.retain(|a| !a.path.eq_ignore_ascii_case(&packet.path));
        match action {
            notify::Action::None => {}
            notify::Action::Allow(seconds) => {
                let item = &mut self.profile.apps[index];
                item.enabled = true;
                item.silent = false;
                item.timer_until = seconds.map_or(0, |s| now_unix() + s);
                done(&mut self.alerts);
                self.changed();
            }
            notify::Action::Block => {
                let item = &mut self.profile.apps[index];
                item.enabled = false;
                item.silent = true;
                done(&mut self.alerts);
                self.save();
                self.dirty = true;
            }
            notify::Action::Silence => {
                self.profile.apps[index].silent = true;
                done(&mut self.alerts);
                self.save();
            }
            notify::Action::CreateRule => {
                done(&mut self.alerts);
                self.show_window();
                self.dialog = Some(Dialog::Rule(RuleDraft::for_connection(
                    app.path.clone(),
                    packet.remote_addr.clone(),
                    packet.protocol,
                    packet.inbound,
                )));
            }
            notify::Action::Reveal => shell::reveal(&app.path),
            notify::Action::Kill => {
                let killed = apps::kill_processes(&app.path);
                self.notify(format!("Ended {killed} process(es) of {}.", app.display_name), false);
                done(&mut self.alerts);
            }
            notify::Action::Next => self.alert_index = (self.alert_index + 1) % self.alerts.len(),
            notify::Action::Dismiss => done(&mut self.alerts),
        }
    }

    /// IsHashesEnabled: an allowed app whose file changes on disk is blocked
    /// again (`_app_queue_hashes`). The hash is taken when the app is allowed and
    /// compared every 10 minutes.
    fn check_file_hashes(&mut self, ctx: &egui::Context) {
        if !self.profile.settings.check_hashes {
            self.hash_baseline.clear();
            return;
        }
        const SWEEP: Duration = Duration::from_secs(10 * 60);
        let sweep = self.last_hash_sweep.elapsed() >= SWEEP;
        if sweep {
            self.last_hash_sweep = Instant::now();
        }
        ctx.request_repaint_after(SWEEP.saturating_sub(self.last_hash_sweep.elapsed()));
        let (mut changed, mut save) = (Vec::new(), false);
        let inspector = &mut self.inspector;
        for app in self.profile.apps.iter_mut().filter(|a| a.kind == AppKind::Regular) {
            let key = app.path.to_lowercase();
            if !app.enabled {
                // Taken again when the app is allowed next time.
                if !app.hash.is_empty() {
                    app.hash.clear();
                    save = true;
                }
                continue;
            }
            if app.hash.is_empty() {
                if self.hash_baseline.insert(key.clone()) {
                    inspector.want_hash(&app.path, true);
                } else if let Some(Some(hash)) = inspector.hash(&app.path) {
                    app.hash = hash;
                    self.hash_baseline.remove(&key);
                    save = true;
                }
                continue;
            }
            if sweep {
                inspector.want_hash(&app.path, true);
            } else if let Some(Some(hash)) = inspector.hash(&app.path) {
                if !hash.eq_ignore_ascii_case(&app.hash) {
                    app.enabled = false;
                    app.timer_until = 0;
                    app.hash = hash;
                    changed.push(app.display_name.clone());
                }
            }
        }
        if !changed.is_empty() {
            self.notify(format!("Changed on disk, so blocked again: {}", changed.join(", ")), true);
            self.changed();
        } else if save {
            self.save();
        }
    }

    /// View > Font: pick the window font and size, as the C build's IDM_FONT does.
    fn choose_font(&mut self, ctx: &egui::Context) {
        let s = &self.profile.settings;
        let Some((face, size)) = shell::choose_font(&s.font, s.font_size) else {
            return;
        };
        if shell::font_file(&face).is_none() {
            self.notify(format!("The font file for {face} was not found; Segoe UI stays."), true);
            return;
        }
        let s = &mut self.profile.settings;
        s.font = face;
        s.font_size = size;
        theme::install_fonts(ctx, &s.language, &s.font);
        theme::set_text_size(ctx, s.font_size);
        self.widths_stale = true;
        self.save();
        self.dirty = true;
    }

    /// IsWUFixEnabled: move the update services to wusvc.exe and allow it, as
    /// `_app_wufixenable` does, or move them back.
    fn set_wu_fix(&mut self, on: bool) {
        if let Err(err) = crate::wufix::set(on) {
            self.notify(err, true);
            return;
        }
        self.profile.settings.wu_fix = on;
        let path = crate::wufix::wusvc_path().to_string_lossy().into_owned();
        let index = match self.profile.apps.iter().position(|a| a.path.eq_ignore_ascii_case(&path)) {
            Some(index) => index,
            None if on => {
                self.profile.apps.push(AppItem::new(path, "wusvc.exe".into(), AppKind::Regular));
                self.profile.apps.len() - 1
            }
            None => return self.changed(),
        };
        let app = &mut self.profile.apps[index];
        app.enabled = on;
        app.pinned = on;
        app.comment = if on { "Windows Update services (Allow Windows Update)".into() } else { String::new() };
        self.changed();
    }

    /// Ask GitHub for a newer release on a background thread. Automatic checks
    /// run at most once a day.
    fn check_for_updates(&mut self, manual: bool) {
        let now = now_unix();
        let s = &mut self.profile.settings;
        if !manual && (!s.check_updates || now.saturating_sub(s.last_update_check) < 24 * 60 * 60) {
            return;
        }
        s.last_update_check = now;
        self.save();
        let tx = self.worker.reply_tx.clone();
        std::thread::spawn(move || {
            let _ = tx.send(Reply::Update { result: crate::update::newer_version(), manual });
        });
    }

    /// IsEnableAppMonitor: add programs to the list as they start, every 5 seconds.
    fn scan_new_apps(&mut self, ctx: &egui::Context) {
        if !self.profile.settings.app_monitor {
            return;
        }
        const PERIOD: Duration = Duration::from_secs(5);
        ctx.request_repaint_after(PERIOD.saturating_sub(self.last_app_scan.elapsed()));
        if self.last_app_scan.elapsed() < PERIOD {
            return;
        }
        self.last_app_scan = Instant::now();
        let known: HashSet<String> = self.profile.apps.iter().map(|a| a.path.to_lowercase()).collect();
        let mut added = false;
        for app in apps::processes() {
            if !known.contains(&app.path.to_lowercase()) {
                self.profile.apps.push(app);
                added = true;
            }
        }
        if added {
            self.save();
            self.dirty = true;
        }
    }

    /// Follow the theme setting (and Windows, for "System"), and note the
    /// window size while it is restored, for next start.
    fn sync_appearance(&mut self, ctx: &egui::Context) {
        let theme = self.profile.settings.theme;
        let dark = match theme {
            1 => true,
            2 => false,
            _ => ctx.system_theme().map_or(self.dark, |t| t == egui::Theme::Dark),
        };
        if dark != self.dark {
            self.dark = dark;
            theme::set_theme(ctx, self.accent, dark, theme == 0);
        }
        let (minimized, maximized, rect) =
            ctx.input(|i| (i.viewport().minimized, i.viewport().maximized, i.viewport().inner_rect));
        if minimized != Some(true) && maximized != Some(true) {
            if let Some(rect) = rect {
                self.window_size = Some(rect.size());
            }
        }
    }

    /// Take the monitor's newest connection table: it refreshes the Connections
    /// tab and the "has a connection" highlight on the app tabs.
    fn sync_connections(&mut self) {
        let s = &self.profile.settings;
        // Byte counts only while the Connections tab is open; they need administrator rights.
        let stats = self.admin && self.tab == Tab::Connections;
        self.monitor.configure(s.network_monitor, s.show_wait_connections, stats, stats && s.udp_traffic);
        if let Some(rows) = self.monitor.latest() {
            let connected: HashSet<String> =
                rows.iter().filter(|c| c.is_live()).map(|c| c.path.to_lowercase()).collect();
            if connected != self.connected {
                self.connected = connected;
                if self.tab.app_kind().is_some() {
                    self.dirty = true;
                }
            }
            if self.tab == Tab::Connections {
                // Rows are replaced wholesale; a selection by index would point elsewhere.
                self.selected[Tab::Connections.index()] = None;
                self.connections = rows;
                self.dirty = true;
            }
        }
        if self.resolver.changed() && self.tab == Tab::Connections {
            self.dirty = true;
        }
    }

    /// Keep the tray icon and menu checkmarks in step with the window.
    fn sync_tray(&mut self, ctx: &egui::Context) {
        let Some(tray) = &self.tray else {
            return;
        };
        let state = tray_state_of(&self.profile, self.filters_on, self.worker.busy());
        if state != self.tray_state {
            tray.set_state(state.clone());
            self.tray_state = state;
        }
        // Minimizing sends the window to the tray, as in the C build.
        let minimized = ctx.input(|i| i.viewport().minimized).unwrap_or(false);
        if self.start_minimized {
            self.start_minimized = false;
            tray.hide_main();
            self.in_tray = true;
        } else if minimized && !self.in_tray {
            tray.hide_main();
            self.in_tray = true;
        } else if !minimized && self.in_tray {
            self.in_tray = false;
        }
    }

    fn handle_tray(&mut self, ctx: &egui::Context) {
        while let Ok(command) = self.tray_rx.try_recv() {
            let s = &mut self.profile.settings;
            match command {
                TrayCommand::ToggleFilters => {
                    self.show_window();
                    self.dialog = Some(Dialog::Confirm(Ask::Filters(!self.filters_on)));
                }
                TrayCommand::Notifications => {
                    s.notifications = !s.notifications;
                    self.save();
                }
                TrayCommand::NotificationSound => {
                    s.notifications_sound = !s.notifications_sound;
                    self.save();
                }
                TrayCommand::FullscreenSilent => {
                    s.notifications_fullscreen_silent = !s.notifications_fullscreen_silent;
                    self.save();
                }
                TrayCommand::LogFile => {
                    s.log_to_file = !s.log_to_file;
                    self.save();
                }
                TrayCommand::LogUi => {
                    let on = !s.log_ui;
                    self.set_log_ui(on);
                }
                TrayCommand::ShowLog => self.show_log(),
                TrayCommand::ClearLog => {
                    self.show_window();
                    self.dialog = Some(Dialog::Confirm(Ask::ClearLog));
                }
                TrayCommand::Settings => self.dialog = Some(Dialog::Settings),
                TrayCommand::Website => shell::open("https://github.com/NitroDiesel/simplewall"),
                TrayCommand::About => self.dialog = Some(Dialog::About),
                TrayCommand::Exit => {
                    self.show_window();
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            }
        }
    }

    /// Bring the window back from the tray, for questions that need an answer.
    fn show_window(&mut self) {
        if let Some(tray) = &self.tray {
            tray.show_main();
        }
        self.in_tray = false;
    }

    /// Ask before closing while timers still hold apps open.
    fn guard_close(&mut self, ctx: &egui::Context) {
        if self.closing || !ctx.input(|i| i.viewport().close_requested()) {
            return;
        }
        let timers = self.profile.apps.iter().filter(|a| a.has_timer()).count();
        let ask = if !self.filters_on {
            None
        } else if timers > 0 {
            Some(Ask::CloseWithTimers(timers))
        } else if self.profile.settings.confirm_exit {
            Some(Ask::Exit)
        } else {
            None
        };
        if let Some(ask) = ask {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            self.show_window();
            self.dialog = Some(Dialog::Confirm(ask));
        }
    }

    fn show_log(&mut self) {
        let path = log::log_path();
        if path.exists() {
            shell::open(&path.to_string_lossy());
        } else {
            self.notify("The log file is empty.", false);
        }
    }

    /// File > Import: this port's profile or the C build's (plain, compressed, or
    /// encrypted). The current profile is kept as profile.before-import.xml.
    fn import_profile(&mut self) {
        let Some(path) = shell::pick_profile_to_open() else {
            return;
        };
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(err) => return self.notify(format!("Could not read {path}: {err}"), true),
        };
        if let Some(saved) = profile::user_path() {
            let _ = profile::export(&self.profile, &saved.with_file_name("profile.before-import.xml"));
        }
        match profile::import(&mut self.profile, &bytes) {
            Ok(found) => {
                self.profile.apps = apps::merge(&self.profile.apps, apps::enumerate());
                self.clear_app_selection();
                self.clear_rule_selection();
                let source = if found.from_original { "simplewall" } else { "this program" };
                self.notify(
                    format!("Imported {} apps and {} user rules from a {source} profile.", found.apps, found.rules),
                    false,
                );
                self.changed();
            }
            Err(err) => self.notify(err, true),
        }
    }

    fn export_profile(&mut self) {
        let Some(path) = shell::pick_profile_to_save() else {
            return;
        };
        match profile::export(&self.profile, std::path::Path::new(&path)) {
            Ok(()) => self.notify(format!("Exported the profile to {path}."), false),
            Err(err) => self.notify(format!("Could not write {path}: {err}"), true),
        }
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

    /// Apps other than System, and user rules, can be deleted.
    fn deletable(&self, id: usize) -> bool {
        if self.tab.app_kind().is_some() {
            self.profile.apps.get(id).is_some_and(|a| a.kind != AppKind::System)
        } else if self.tab.rule_origin().is_some() {
            self.profile.rules.get(id).is_some_and(|r| r.origin == RuleOrigin::User)
        } else {
            false
        }
    }

    /// Delete asks first, as the C build does; there is no undo.
    fn ask_delete(&mut self, id: usize) {
        if self.deletable(id) {
            self.dialog = Some(Dialog::Confirm(Ask::Delete(id)));
        }
    }

    fn delete(&mut self, id: usize) {
        if !self.deletable(id) {
            return;
        }
        if self.tab.app_kind().is_some() {
            self.profile.apps.remove(id);
            self.clear_app_selection();
        } else {
            self.profile.rules.remove(id);
            self.clear_rule_selection();
        }
        self.changed();
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
                .map(|p| format!("{}\t{}\t{}", p.path, p.local(), p.remote())),
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
            // egui reports Ctrl+X, with or without Shift, as a Cut event, not a key press.
            let cut = i.events.iter().any(|e| matches!(e, Event::Cut));
            if i.consume_key(ctrl_shift, Key::X) || (cut && i.modifiers.shift && !typing) {
                actions.push(Action::PurgeUnused);
            } else if cut && !typing {
                // Ctrl+X clears the log in the C build (asks first here, #2109).
                actions.push(Action::ClearLog);
            }
            if i.consume_key(Modifiers::CTRL, Key::I) {
                actions.push(Action::ShowLog);
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
                Action::Find => {
                    // Ctrl+F brings a hidden search bar back.
                    self.profile.settings.show_search_bar = true;
                    ctx.memory_mut(|m| m.request_focus(Id::new(FIND_ID)));
                }
                Action::Refresh => self.refresh(),
                Action::Settings => self.dialog = Some(Dialog::Settings),
                Action::About => self.dialog = Some(Dialog::About),
                Action::NextTab | Action::PrevTab => {
                    let step = if matches!(action, Action::NextTab) { 1 } else { Tab::ALL.len() - 1 };
                    self.switch_tab(Tab::ALL[(self.tab.index() + step) % Tab::ALL.len()]);
                }
                Action::PurgeUnused => self.ask_purge_unused(),
                Action::PurgeTimers => self.purge_timers(),
                Action::ShowLog => self.show_log(),
                Action::ClearLog => self.dialog = Some(Dialog::Confirm(Ask::ClearLog)),
                Action::Delete => selected.into_iter().for_each(|id| self.ask_delete(id)),
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
            .frame(egui::Frame::NONE.fill(theme::chrome()).inner_margin(Margin::symmetric(6, 2)))
            .show_separator_line(false)
            .show(ctx, |ui| {
                egui::menu::bar(ui, |ui| {
                    ui.spacing_mut().button_padding = vec2(8.0, 3.0);
                    ui.menu_button(t("File"), |ui| {
                        if ui.button(format!("{}\u{2026}", t("Add app"))).clicked() {
                            ui.close_menu();
                            self.add_app();
                        }
                        if ui.add(egui::Button::new(format!("{}\u{2026}", t("Settings"))).shortcut_text("F2")).clicked() {
                            ui.close_menu();
                            self.dialog = Some(Dialog::Settings);
                        }
                        ui.separator();
                        if ui.button(format!("{}\u{2026}", t("Import"))).clicked() {
                            ui.close_menu();
                            self.import_profile();
                        }
                        if ui.button(format!("{}\u{2026}", t("Export"))).clicked() {
                            ui.close_menu();
                            self.export_profile();
                        }
                        ui.separator();
                        if ui.button(t("Exit")).clicked() {
                            ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                        }
                    });
                    ui.menu_button(t("Edit"), |ui| {
                        if ui.add(egui::Button::new(format!("{}\u{2026}", crate::i18n::t_as("Search", "Find"))).shortcut_text("Ctrl+F")).clicked() {
                            ui.close_menu();
                            ui.ctx().memory_mut(|m| m.request_focus(Id::new(FIND_ID)));
                        }
                        if ui.add(egui::Button::new(t("Refresh")).shortcut_text("F5")).clicked() {
                            ui.close_menu();
                            self.refresh();
                        }
                        ui.separator();
                        if ui.add(egui::Button::new(t("Purge unused apps")).shortcut_text("Ctrl+Shift+X")).clicked() {
                            ui.close_menu();
                            self.ask_purge_unused();
                        }
                        if ui.add(egui::Button::new(t("Purge timers")).shortcut_text("Ctrl+Shift+T")).clicked() {
                            ui.close_menu();
                            self.purge_timers();
                        }
                    });
                    // The C build's View menu.
                    ui.menu_button(t("View"), |ui| {
                        let mut language = None;
                        let mut pick_font = false;
                        let s = &mut self.profile.settings;
                        let mut save = ui.checkbox(&mut s.always_on_top, t("Always on top")).changed();
                        let mut dark = self.dark;
                        if ui.checkbox(&mut dark, t("Use dark theme")).changed() {
                            s.theme = if dark { 1 } else { 2 };
                            save = true;
                        }
                        save |= ui.checkbox(&mut s.autosize_columns, t("Autosize columns")).changed();
                        save |= ui.checkbox(&mut s.show_filenames_only, t("Show filenames only")).changed();
                        if ui.checkbox(&mut s.show_search_bar, t("Show search bar")).changed() {
                            // A hidden search must not keep filtering the list.
                            if !s.show_search_bar {
                                self.query.clear();
                            }
                            save = true;
                        }
                        ui.separator();
                        ui.menu_button(t("Icons"), |ui| {
                            for (value, label) in [(0, t("Details")), (1, t("Icons")), (2, t("Tiles"))] {
                                save |= ui.radio_value(&mut s.view_type, value, label).changed();
                            }
                            ui.separator();
                            for (value, label) in [(0, t("Small")), (1, t("Large")), (2, t("Extra large"))] {
                                save |= ui.radio_value(&mut s.icon_size, value, label).changed();
                            }
                            ui.separator();
                            save |= ui.checkbox(&mut s.hide_icons, t("Do not load icons")).changed();
                        });
                        ui.menu_button(t("Language"), |ui| {
                            let current = if s.language.is_empty() { "English" } else { s.language.as_str() };
                            for name in crate::i18n::languages() {
                                if ui.radio(current == name, name).clicked() {
                                    language = Some(if name == "English" { String::new() } else { name.to_string() });
                                    ui.close_menu();
                                }
                            }
                        });
                        ui.separator();
                        if ui.button(format!("{}\u{2026}", t("Font"))).clicked() {
                            ui.close_menu();
                            pick_font = true;
                        }
                        if let Some(language) = language.filter(|l| *l != s.language) {
                            s.language = language;
                            crate::i18n::set_language(&s.language);
                            theme::install_fonts(ui.ctx(), &s.language, &s.font);
                            save = true;
                        }
                        if save {
                            self.save();
                            self.dirty = true;
                        }
                        if pick_font {
                            self.choose_font(ui.ctx());
                        }
                    });
                    ui.menu_button(t("Settings"), |ui| {
                        let s = &mut self.profile.settings;
                        let mut changed = false;
                        changed |= ui.checkbox(&mut s.allow_loopback, t("Allow loopback connections for all")).changed();
                        changed |= ui.checkbox(&mut s.allow_ipv6, t("Allow IPv6 redirections (6to4) for all")).changed();
                        changed |= ui.checkbox(&mut s.allow_lan, "Allow local network (LAN)").changed();
                        let mut wu_fix = s.wu_fix;
                        let wu_toggled = ui.checkbox(&mut wu_fix, t("Allow Windows Update")).changed();
                        ui.separator();
                        changed |= ui.checkbox(&mut s.block_outbound, t("Block outbound connections for all")).changed();
                        changed |= ui.checkbox(&mut s.block_inbound, t("Block inbound connections for all")).changed();
                        changed |= ui.checkbox(&mut s.stealth_mode, "Use stealth mode").changed();
                        ui.separator();
                        changed |= ui
                            .checkbox(&mut s.user_allows_override_blocklist, "User rules take priority over blocklist")
                            .changed();
                        ui.separator();
                        let mut format_changed = false;
                        ui.menu_button(t("Profile type"), |ui| {
                            for (value, label) in [(0, t("Plain")), (1, t("Compressed")), (2, t("Encrypted"))] {
                                format_changed |= ui.radio_value(&mut s.profile_type, value, label).changed();
                            }
                        });
                        ui.separator();
                        if ui.button("All settings\u{2026}").clicked() {
                            ui.close_menu();
                            self.dialog = Some(Dialog::Settings);
                        }
                        if wu_toggled {
                            self.set_wu_fix(wu_fix);
                        } else if changed {
                            self.changed();
                        } else if format_changed {
                            // Rewrite the profile in the new format right away.
                            self.save();
                        }
                    });
                    ui.menu_button(t("Blocklist"), |ui| {
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
                    ui.menu_button(t("Help"), |ui| {
                        if ui.button(t("Website")).clicked() {
                            ui.close_menu();
                            shell::open("https://github.com/NitroDiesel/simplewall");
                        }
                        if ui.button(t("Check for updates")).clicked() {
                            ui.close_menu();
                            self.check_for_updates(true);
                        }
                        if let Some(version) = &self.update_available {
                            if ui.button(format!("Download update ({version})")).clicked() {
                                ui.close_menu();
                                shell::open(crate::update::RELEASES_URL);
                            }
                        }
                        if ui.add(egui::Button::new(t("About")).shortcut_text("F1")).clicked() {
                            ui.close_menu();
                            self.dialog = Some(Dialog::About);
                        }
                    });
                });
            });
    }

    fn toolbar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("toolbar")
            .frame(egui::Frame::NONE.fill(theme::chrome()).inner_margin(Margin::symmetric(6, 4)))
            .show_separator_line(false)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 2.0;
                    let accent = self.accent;
                    let (icon, label) = if self.filters_on {
                        (&self.icons.shield_off, crate::i18n::t_as("Disable filters", "Disable filtering"))
                    } else {
                        (&self.icons.shield_on, crate::i18n::t_as("Enable filters", "Enable filtering"))
                    };
                    let icon = icon.clone();
                    if tool_button(ui, &icon, Some(label), "Enable or disable filtering", None, accent).clicked() {
                        self.dialog = Some(Dialog::Confirm(Ask::Filters(!self.filters_on)));
                    }
                    tool_separator(ui);
                    let plus = self.icons.plus.clone();
                    if tool_button(ui, &plus, None, t("Create rule"), None, accent).clicked() {
                        let apps = self.selected_app_path().into_iter().collect();
                        self.dialog = Some(Dialog::Rule(RuleDraft::new(apps)));
                    }
                    tool_separator(ui);
                    let alert = self.icons.error.clone();
                    let notifications = self.profile.settings.notifications;
                    if tool_button(ui, &alert, None, t("Enable packets notifications"), Some(notifications), accent).clicked() {
                        self.profile.settings.notifications = !notifications;
                        self.save();
                    }
                    let note = self.icons.note.clone();
                    let log_file = self.profile.settings.log_to_file;
                    if tool_button(ui, &note, None, "Log to file", Some(log_file), accent).clicked() {
                        self.profile.settings.log_to_file = !log_file;
                        self.save();
                    }
                    let eye = self.icons.eye.clone();
                    let log_ui = self.profile.settings.log_ui;
                    if tool_button(ui, &eye, None, "Log to UI (Packets log)", Some(log_ui), accent).clicked() {
                        self.set_log_ui(!log_ui);
                    }
                    tool_separator(ui);
                    let refresh = self.icons.refresh.clone();
                    if tool_button(ui, &refresh, None, "Refresh (F5)", None, accent).clicked() {
                        self.refresh();
                    }
                    let settings = self.icons.settings.clone();
                    if tool_button(ui, &settings, None, "Settings (F2)", None, accent).clicked() {
                        self.dialog = Some(Dialog::Settings);
                    }
                    tool_separator(ui);
                    let show = self.icons.log_show.clone();
                    if tool_button(ui, &show, None, "Show log (Ctrl+I)", None, accent).clicked() {
                        self.show_log();
                    }
                    let clear = self.icons.log_clear.clone();
                    if tool_button(ui, &clear, None, "Clear log (Ctrl+X)", None, accent).clicked() {
                        self.dialog = Some(Dialog::Confirm(Ask::ClearLog));
                    }

                    if self.profile.settings.show_search_bar {
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            self.search_box(ui);
                        });
                    }
                });
            });
    }

    fn set_log_ui(&mut self, on: bool) {
        self.profile.settings.log_ui = on;
        self.save();
        if let Err(err) = wfp::set_event_collection(on) {
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
        // It takes what the toolbar leaves, so it is never cut off at the window edge.
        let width = (ui.available_width() - SEARCH_ICON_GUTTER - 18.0).clamp(60.0, 260.0);
        let find = crate::i18n::t_as("Search", "Find");
        let hint = if width < 170.0 { format!("{find}\u{2026}") } else { format!("{find}\u{2026} (Ctrl+F)") };
        let edit = egui::TextEdit::singleline(&mut self.query)
            .id(Id::new(FIND_ID))
            .hint_text(hint)
            .desired_width(width)
            .margin(Margin { left: 10, right: SEARCH_ICON_GUTTER as i8, top: 6, bottom: 6 });
        let response = ui.add(edit);
        // The response rect excludes the margins; the frame does not.
        let frame_right = response.rect.right() + SEARCH_ICON_GUTTER;
        let center = pos2(frame_right - SEARCH_ICON_GUTTER / 2.0, response.rect.center().y);
        if self.query.is_empty() {
            // Magnifier, drawn so it takes the text color.
            let color = if response.has_focus() { theme::text() } else { theme::text_muted() };
            let stroke = Stroke::new(1.5_f32, color);
            let lens = center + vec2(-1.5, -1.5);
            ui.painter().circle_stroke(lens, 4.5, stroke);
            ui.painter().line_segment([lens + vec2(3.3, 3.3), lens + vec2(7.0, 7.0)], stroke);
        } else {
            // The C build's clear button.
            let rect = Rect::from_center_size(center, vec2(20.0, 20.0));
            let clear = ui.interact(rect, Id::new("find_clear"), Sense::click());
            clear.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Button, true, "Clear search"));
            let hover = ui.ctx().animate_bool_with_time(clear.id, clear.hovered(), theme::motion(HOVER_FADE));
            if hover > 0.0 {
                ui.painter().rect_filled(rect, 4.0, theme::overlay(hover));
            }
            let icon = Rect::from_center_size(center, vec2(14.0, 14.0));
            let uv = Rect::from_min_max(pos2(0.0, 0.0), pos2(1.0, 1.0));
            ui.painter().image(self.icons.search.id(), icon, uv, Color32::WHITE);
            if clear.on_hover_text("Clear search").clicked() {
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
            .frame(egui::Frame::NONE.fill(theme::chrome()).inner_margin(Margin { left: 6, right: 6, top: 2, bottom: 0 }))
            .show_separator_line(false)
            .show(ctx, |ui| {
                let mut active = None;
                let mut clicked = None;
                let bar = ui
                    .horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 2.0;
                        let galleys: Vec<_> = Tab::ALL
                            .iter()
                            .map(|tab| {
                                let font = theme::body(theme::BODY);
                                ui.painter().layout_no_wrap(tab.label().into(), font, theme::text())
                            })
                            .collect();
                        // Tighten the padding so all eight tabs fit at the minimum window width.
                        let text: f32 = galleys.iter().map(|g| g.size().x).sum();
                        let spacing = ui.spacing().item_spacing.x * (Tab::ALL.len() - 1) as f32;
                        let room = (ui.available_width() - text - spacing) / Tab::ALL.len() as f32;
                        let padding = room.clamp(10.0, 26.0);
                        for (tab, galley) in Tab::ALL.into_iter().zip(galleys) {
                            let selected = tab == self.tab;
                            let (rect, response) =
                                ui.allocate_exact_size(vec2(galley.size().x + padding, 34.0), Sense::click());
                            let name = tab.label();
                            response.widget_info(|| egui::WidgetInfo::selected(egui::WidgetType::SelectableLabel, true, selected, name));
                            let hover = ui.ctx().animate_bool_with_time(response.id, response.hovered(), theme::motion(HOVER_FADE));
                            if hover > 0.0 && !selected {
                                let fill = theme::overlay(0.65 * hover);
                                ui.painter().rect_filled(rect.shrink2(vec2(0.0, 4.0)), 4.0, fill);
                            }
                            let color = if selected {
                                theme::text()
                            } else {
                                lerp_color(theme::text_muted(), theme::text(), hover)
                            };
                            let pos = rect.center() - galley.size() / 2.0;
                            // The underline spans the label plus 3px on each side.
                            let label = Rangef::new(pos.x - 3.0, pos.x + galley.size().x + 3.0);
                            ui.painter().galley(pos, galley, color);
                            if selected {
                                active = Some(label);
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
                    Stroke::new(1.0_f32, theme::border()),
                );
                if let Some(target) = active {
                    let drawn = self.slide_underline(ui.ctx(), target);
                    let rect = Rect::from_x_y_ranges(drawn, bar.bottom() - 3.0..=bar.bottom());
                    ui.painter().rect_filled(rect, CornerRadius::same(2), theme::accent_ink(self.accent));
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
        let slide = theme::motion(TAB_SLIDE as f32) as f64;
        let line = self.underline.get_or_insert(Underline { tab, drawn: target, from: target, start: now - slide });
        if line.tab != tab {
            line.tab = tab;
            line.from = line.drawn;
            line.start = now;
        }
        let t = if slide > 0.0 { ((now - line.start) / slide).clamp(0.0, 1.0) as f32 } else { 1.0 };
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

    /// The focused control gets a 2 px ring in the text color, which reads on
    /// every surface, while the keyboard is in use (a click hides it again).
    fn focus_ring(&mut self, ctx: &egui::Context) {
        ctx.input(|i| {
            for event in &i.events {
                match event {
                    Event::Key { key: Key::Tab, pressed: true, .. } => self.keyboard = true,
                    Event::PointerButton { pressed: true, .. } => self.keyboard = false,
                    _ => {}
                }
            }
        });
        if !self.keyboard {
            return;
        }
        let Some(focused) = ctx.read_response(match ctx.memory(|m| m.focused()) {
            Some(id) => id,
            None => return,
        }) else {
            return;
        };
        let painter = ctx.layer_painter(egui::LayerId::new(egui::Order::Tooltip, Id::new("focus_ring")));
        painter.rect_stroke(
            focused.rect.expand(2.0),
            CornerRadius::same(5),
            Stroke::new(2.0_f32, theme::text()),
            egui::StrokeKind::Outside,
        );
    }

    fn status_bar(&mut self, ctx: &egui::Context) {
        let (text, color, dot) = self.status_text();
        egui::TopBottomPanel::bottom("status")
            .exact_height(26.0)
            .frame(egui::Frame::NONE.fill(theme::chrome()).inner_margin(Margin::symmetric(10, 0)))
            .show_separator_line(false)
            .show(ctx, |ui| {
                let full = ui.max_rect();
                ui.painter().hline(
                    full.x_range().expand(10.0),
                    full.top() + 0.5,
                    Stroke::new(1.0_f32, theme::border()),
                );
                let part = 170.0;
                let first = (full.width() - part * 2.0).max(220.0);
                let painter = ui.painter();
                let y = full.center().y;
                painter.circle_filled(pos2(full.left() + 4.0, y), 3.5, dot);
                // The message stops before the counters; the whole text is in its tooltip.
                let room = Rect::from_min_max(pos2(full.left(), full.top()), pos2(full.left() + first - 10.0, full.bottom()));
                let mut job = egui::text::LayoutJob::simple_singleline(text.clone(), theme::body(theme::SMALL), color);
                job.wrap = egui::text::TextWrapping::truncate_at_width(room.width() - 16.0);
                let galley = painter.layout_job(job);
                let cut = galley.elided;
                painter.galley(pos2(full.left() + 16.0, y - galley.size().y / 2.0), galley, color);
                let error = self.notice.as_ref().is_some_and(|n| n.error);
                let message = ui.interact(room, Id::new("status_message"), if error { Sense::click() } else { Sense::hover() });
                let message = match (cut, error) {
                    (_, true) => message.on_hover_text(format!("{text}\n\nClick to dismiss.")),
                    (true, false) => message.on_hover_text(&text),
                    (false, false) => message,
                };
                if message.clicked() {
                    self.notice = None;
                }
                let parts = [
                    format!("{}: {}", t("Unused apps"), self.unused),
                    format!("{}: {}", t("Apps with timer"), self.timers),
                ];
                for (i, label) in parts.into_iter().enumerate() {
                    let x = full.left() + first + part * i as f32;
                    painter.vline(x, full.top() + 6.0..=full.bottom() - 6.0, Stroke::new(1.0_f32, theme::border()));
                    let galley = painter.layout_no_wrap(label, theme::body(theme::SMALL), theme::text_muted());
                    painter.galley(pos2(x + 10.0, y - galley.size().y / 2.0), galley, theme::text_muted());
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
            return (format!("{}\u{2026}", t("Applying filters")), theme::text(), self.accent);
        }
        if let Some(notice) = &self.notice {
            let color = if notice.error { theme::danger() } else { theme::text() };
            return (notice.text.clone(), color, if notice.error { theme::danger() } else { self.accent });
        }
        if self.filters_on {
            let text = if self.profile.settings.filters_temporary {
                t("Filters are enabled until reboot.")
            } else {
                t("Filters are enabled.")
            };
            (text.into(), theme::text(), Color32::from_rgb(0x6C, 0xCB, 0x5F))
        } else {
            (t("Filters are disabled!").into(), theme::text(), theme::danger())
        }
    }

    fn list(&mut self, ctx: &egui::Context) {
        let index = self.tab.index();
        let empty = self.empty_text();
        let columns = self.tab.columns_for(self.admin);
        let s = &self.profile.settings;
        if s.autosize_columns && self.widths_stale {
            self.auto_widths = list::measure_columns(ctx, columns, &self.lines);
            self.widths_stale = false;
        }
        let look = list::Look {
            view: list::View::from_setting(s.view_type),
            icon: match s.icon_size {
                1 => 32.0,
                2 => 48.0,
                _ => 16.0,
            },
            hide_icons: s.hide_icons,
            auto_widths: s.autosize_columns.then_some(self.auto_widths.as_slice()),
        };
        let output = egui::CentralPanel::default()
            .frame(egui::Frame::NONE.fill(theme::surface()))
            .show(ctx, |ui| {
                let mut art = list::Art {
                    icons: &self.icons,
                    files: &mut self.files,
                    accent: self.accent,
                };
                List {
                    id: Id::new(("list", index)),
                    columns,
                    lines: &self.lines,
                    sort: self.sorts[index],
                    selected: self.selected[index],
                    scroll_to: self.scroll_to.take(),
                    empty: &empty,
                    look,
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
        // Each says what fills the tab, and what to do when that cannot happen yet.
        match self.tab {
            Tab::Packets if !self.profile.settings.log_ui => {
                "Blocked connections are listed here when Log to UI is on (the eye in the toolbar).".into()
            }
            Tab::Packets if !self.filters_on => {
                "Blocked connections appear here while filtering is on. Select Enable filtering to start.".into()
            }
            Tab::Packets => "No blocked connections yet.".into(),
            Tab::Connections if !self.profile.settings.network_monitor => {
                "The connection monitor is off. Turn it on in Settings > Connections.".into()
            }
            Tab::Connections => "No active connections.".into(),
            Tab::User => "No user rules. Use + in the toolbar to create one.".into(),
            Tab::Apps => "No apps yet. Apps appear here when they first connect, or use File > Add app.".into(),
            Tab::Services | Tab::Uwp => "None found on this computer.".into(),
            _ => "No rules in this group.".into(),
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
            ui.menu_button(t("Timer"), |ui| {
                for (seconds, label) in TIMERS {
                    if ui.button(label).clicked() {
                        ui.close_menu();
                        self.set_timer(id, seconds);
                    }
                }
                if app.has_timer() {
                    ui.separator();
                    if ui.button(t("Disable timer")).clicked() {
                        ui.close_menu();
                        // Ending a timer blocks the app again, as `_app_timer_reset` does
                        // (henrypp/simplewall#2159).
                        if let Some(app) = self.profile.apps.get_mut(id) {
                            app.timer_until = 0;
                            app.enabled = false;
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
                && ui.add(egui::Button::new(t("Open containing folder")).shortcut_text("Ctrl+E")).clicked()
            {
                ui.close_menu();
                self.explore(id);
            }
            ui.separator();
            if ui.add(egui::Button::new(t("Copy")).shortcut_text("Ctrl+C")).clicked() {
                ui.close_menu();
                ui.ctx().copy_text(app.path.clone());
            }
            if app.kind != AppKind::System && ui.add(egui::Button::new(t("Delete")).shortcut_text("Del")).clicked() {
                ui.close_menu();
                self.ask_delete(id);
            }
        } else if self.tab.rule_origin().is_some() {
            let Some(rule) = self.profile.rules.get(id).cloned() else {
                return;
            };
            let label = if rule.enabled { "Disable rule" } else { t("Enable rule") };
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
            if ui.add(egui::Button::new(t("Copy")).shortcut_text("Ctrl+C")).clicked() {
                ui.close_menu();
                if let Some(text) = self.copy_text(id) {
                    ui.ctx().copy_text(text);
                }
            }
            if rule.origin == RuleOrigin::User && ui.add(egui::Button::new(t("Delete")).shortcut_text("Del")).clicked() {
                ui.close_menu();
                self.ask_delete(id);
            }
        } else if ui.add(egui::Button::new(t("Copy")).shortcut_text("Ctrl+C")).clicked() {
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
                let startup = self.startup.get_or_insert_with(dialogs::Startup::read);
                let effect = dialogs::settings(ctx, &mut self.profile, startup);
                let after = &self.profile.settings;
                if before != *after {
                    self.dirty = true;
                }
                if before.check_revocation != after.check_revocation {
                    self.inspector.reset_signatures();
                    self.dirty = true;
                }
                if before.wu_fix != after.wu_fix {
                    let on = after.wu_fix;
                    // Applied by set_wu_fix, which keeps the old value if the change fails.
                    self.profile.settings.wu_fix = before.wu_fix;
                    self.set_wu_fix(on);
                }
                let after = &self.profile.settings;
                if before.language != after.language {
                    crate::i18n::set_language(&after.language);
                    theme::install_fonts(ctx, &after.language, &after.font);
                    self.dirty = true;
                }
                for group in BlocklistGroup::all() {
                    if before.blocklist(group) != self.profile.settings.blocklist(group) {
                        self.profile.apply_blocklist(group);
                    }
                }
                effect
            }
            Dialog::About => dialogs::about(ctx, &self.icons.logo),
            Dialog::Confirm(ask) => dialogs::confirm(ctx, *ask, self.accent),
        };
        let keep = match effect {
            Effect::None => true,
            Effect::Close => false,
            Effect::Changed => {
                self.changed();
                true
            }
            Effect::Saved => {
                self.save();
                true
            }
            Effect::Error(err) => {
                self.notify(err, true);
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
            Effect::Accept(ask, temporary) => {
                match ask {
                    Ask::Filters(enable) => self.set_filters(enable, temporary),
                    Ask::PurgeUnused(_) => self.purge_unused(),
                    Ask::ClearLog => self.clear_log(),
                    Ask::Delete(id) => self.delete(id),
                    Ask::CloseWithTimers(_) => self.end_timers_and_close(ctx),
                    Ask::Exit => {
                        if temporary {
                            self.profile.settings.confirm_exit = false;
                            self.save();
                        }
                        self.closing = true;
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                }
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
    /// Remember the tab, sort orders, and window size for next time.
    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        let s = &mut self.profile.settings;
        s.current_tab = self.tab.index() as u64;
        s.sorts = self
            .sorts
            .iter()
            .map(|sort| format!("{}:{}", sort.column, u8::from(sort.descending)))
            .collect::<Vec<_>>()
            .join(",");
        if let Some(size) = self.window_size {
            (s.window_width, s.window_height) = (size.x.round() as u64, size.y.round() as u64);
        }
        let _ = profile::save(&self.profile);
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_worker();
        self.tick_timers(ctx);
        self.handle_tray(ctx);
        self.sync_tray(ctx);
        self.sync_events(ctx);
        if self.on_top != self.profile.settings.always_on_top {
            self.on_top = self.profile.settings.always_on_top;
            let level = if self.on_top { egui::WindowLevel::AlwaysOnTop } else { egui::WindowLevel::Normal };
            ctx.send_viewport_cmd(egui::ViewportCommand::WindowLevel(level));
        }
        self.drain_events();
        if self.inspector.changed() {
            self.dirty = true;
        }
        self.check_file_hashes(ctx);
        self.sync_connections();
        self.sync_appearance(ctx);
        self.scan_new_apps(ctx);
        self.guard_close(ctx);
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
        self.alerts_ui(ctx);
        self.focus_ring(ctx);
        if self.dirty {
            ctx.request_repaint();
        }
    }
}

/// Toolbar button: 20px icon, optional label, hover fade, 0.96 press scale.
/// `checked` is Some for an on/off button.
fn tool_button(ui: &mut Ui, icon: &TextureHandle, label: Option<&str>, tip: &str, checked: Option<bool>, accent: Color32) -> Response {
    let font = theme::body(theme::BODY);
    let galley = label.map(|l| ui.painter().layout_no_wrap(l.into(), font, theme::text()));
    let width = 10.0 + 20.0 + galley.as_ref().map_or(0.0, |g| 8.0 + g.size().x) + 10.0;
    let (rect, response) = ui.allocate_exact_size(vec2(width, 34.0), Sense::click());
    let name = label.unwrap_or(tip);
    response.widget_info(|| match checked {
        Some(on) => egui::WidgetInfo::selected(egui::WidgetType::Checkbox, true, on, name),
        None => egui::WidgetInfo::labeled(egui::WidgetType::Button, true, name),
    });
    let checked = checked.unwrap_or(false);
    let hover = ui.ctx().animate_bool_with_time(response.id, response.hovered(), theme::motion(HOVER_FADE));
    let scale = if response.is_pointer_button_down_on() { 0.96 } else { 1.0 };
    let body = Rect::from_center_size(rect.center(), rect.size() * scale);
    let painter = ui.painter();
    if checked {
        painter.rect_filled(body, 5.0, accent.gamma_multiply(0.22));
        painter.rect_stroke(body, 5.0, Stroke::new(1.0_f32, accent.gamma_multiply(0.55)), egui::StrokeKind::Inside);
    }
    if hover > 0.0 {
        painter.rect_filled(body, 5.0, theme::overlay(0.9 * hover));
    }
    let icon_size = 20.0 * scale;
    let icon_left = body.left() + 10.0 * scale;
    let icon_rect = Rect::from_min_size(pos2(icon_left, body.center().y - icon_size / 2.0), vec2(icon_size, icon_size));
    painter.image(icon.id(), icon_rect, Rect::from_min_max(pos2(0.0, 0.0), pos2(1.0, 1.0)), Color32::WHITE);
    if let Some(galley) = galley {
        let pos = pos2(icon_rect.right() + 8.0, body.center().y - galley.size().y / 2.0);
        painter.galley(pos, galley, theme::text());
    }
    response.on_hover_text(tip)
}

fn tool_separator(ui: &mut Ui) {
    let (rect, _) = ui.allocate_exact_size(vec2(11.0, 34.0), Sense::hover());
    ui.painter().vline(rect.center().x, rect.top() + 8.0..=rect.bottom() - 8.0, Stroke::new(1.0_f32, theme::border()));
}

fn lerp_color(a: Color32, b: Color32, t: f32) -> Color32 {
    let mix = |x: u8, y: u8| (x as f32 + (y as f32 - x as f32) * t).round() as u8;
    Color32::from_rgb(mix(a.r(), b.r()), mix(a.g(), b.g()), mix(a.b(), b.b()))
}

/// The native handle of the main window, for the tray to minimize and restore it.
fn main_hwnd(cc: &eframe::CreationContext<'_>) -> Option<isize> {
    use raw_window_handle::{HasWindowHandle, RawWindowHandle};
    match cc.window_handle().ok()?.as_raw() {
        RawWindowHandle::Win32(handle) => Some(handle.hwnd.get()),
        _ => None,
    }
}

fn tray_state_of(profile: &Profile, filters_on: bool, busy: bool) -> TrayState {
    let s = &profile.settings;
    TrayState {
        filters_on,
        busy,
        notifications: s.notifications,
        sound: s.notifications_sound,
        fullscreen_silent: s.notifications_fullscreen_silent,
        log_file: s.log_to_file,
        log_ui: s.log_ui,
        single_click: s.tray_single_click,
    }
}

/// A new list entry for an app seen in a drop event ("apps collector" in `_app_logthread`).
fn app_from_packet(packet: &Packet) -> AppItem {
    let path = match packet.kind {
        // Event paths are lowercase; use the name as it is on disk.
        AppKind::Regular => std::fs::canonicalize(&packet.path)
            .ok()
            .map(|p| {
                let text = p.to_string_lossy().into_owned();
                match text.strip_prefix(r"\\?\UNC\") {
                    Some(rest) => format!(r"\\{rest}"),
                    None => text.trim_start_matches(r"\\?\").to_string(),
                }
            })
            .unwrap_or_else(|| packet.path.clone()),
        _ => packet.path.clone(),
    };
    let name = match packet.kind {
        AppKind::Regular => path.rsplit('\\').next().unwrap_or(&path).to_string(),
        _ => path.clone(),
    };
    AppItem::new(path, name, packet.kind)
}
