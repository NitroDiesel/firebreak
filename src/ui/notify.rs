//! Notification for a blocked app, like the C build's notification dialog:
//! the app, its path, address, port, protocol, direction, and date, with Allow
//! (optionally for a while), Block, and a menu of the less common actions.
//! It is a separate small always-on-top window above the notification area, so
//! it appears while the main window sits in the tray.

use eframe::egui::{self, pos2, vec2, Align, Color32, Layout, RichText, Sense, Stroke, ViewportBuilder};

use crate::model::{protocol_label, AppItem};
use crate::netevents::Packet;

use super::dialogs::TIMERS;
use super::list::FileIcons;
use super::shell;
use super::theme;

pub const WIDTH: f32 = 420.0;
/// Header, buttons, and margins; each detail row adds `ROW`.
const BASE_HEIGHT: f32 = 166.0;
const ROW: f32 = 22.0;

impl Alert<'_> {
    /// Window height for this alert's rows.
    pub fn height(&self) -> f32 {
        let rows = 5 + usize::from(self.signature.is_some()) + usize::from(self.host.is_some());
        BASE_HEIGHT + rows as f32 * ROW
    }
}

pub enum Action {
    None,
    /// Allow the app, for this many seconds if set.
    Allow(Option<u64>),
    /// Keep it blocked and stop notifying (the C build's Block button).
    Block,
    /// Stop notifying without changing access.
    Silence,
    CreateRule,
    Reveal,
    Kill,
    Next,
    Dismiss,
}

/// Bottom-right of the work area, in points.
pub fn builder(ctx: &egui::Context, height: f32) -> ViewportBuilder {
    let mut builder = ViewportBuilder::default()
        .with_title("simplewall")
        .with_decorations(false)
        .with_always_on_top()
        .with_taskbar(false)
        .with_resizable(false)
        .with_active(false)
        .with_inner_size([WIDTH, height]);
    if let Some(area) = shell::work_area() {
        let ppp = ctx.input(|i| i.viewport().native_pixels_per_point).unwrap_or(1.0);
        let margin = 12.0;
        let x = area.right as f32 / ppp - WIDTH - margin;
        let y = area.bottom as f32 / ppp - height - margin;
        builder = builder.with_position(pos2(x, y));
    }
    builder
}

pub struct Alert<'a> {
    pub packet: &'a Packet,
    pub app: &'a AppItem,
    pub position: usize,
    pub count: usize,
    pub accent: Color32,
    /// Outer None: not checked; inner None: not signed.
    pub signature: Option<Option<String>>,
    /// Host name of the remote address, once looked up.
    pub host: Option<String>,
}

pub fn show(ctx: &egui::Context, alert: &Alert, files: &mut FileIcons) -> Action {
    let mut action = Action::None;
    let frame = egui::Frame::NONE
        .fill(theme::RAISED)
        .stroke(Stroke::new(1.0_f32, theme::BORDER))
        .inner_margin(14);
    egui::CentralPanel::default().frame(frame).show(ctx, |ui| {
        let p = alert.packet;
        // Header: icon, name, what happened, position, close. Drag it to move the window.
        let header = ui
            .horizontal(|ui| {
                let mut budget = 2;
                let icon = files.get(ctx, &icon_path(alert.app), alert.app.kind != crate::model::AppKind::Regular, &mut budget);
                match icon {
                    Some(Some(texture)) => {
                        ui.add(egui::Image::new((texture, vec2(32.0, 32.0))));
                    }
                    _ => {
                        ui.add_space(32.0);
                        ctx.request_repaint();
                    }
                }
                ui.vertical(|ui| {
                    ui.label(RichText::new(&alert.app.display_name).font(theme::semibold(15.0)));
                    let what = format!("Blocked {} connection", p.direction().to_lowercase());
                    ui.label(RichText::new(what).small().color(theme::TEXT_MUTED));
                });
                ui.with_layout(Layout::right_to_left(Align::Min), |ui| {
                    let (rect, close) = ui.allocate_exact_size(vec2(22.0, 22.0), Sense::click());
                    if close.hovered() {
                        ui.painter().rect_filled(rect, 4.0, Color32::from_white_alpha(18));
                    }
                    let c = rect.center();
                    let stroke = Stroke::new(1.5_f32, if close.hovered() { theme::TEXT } else { theme::TEXT_MUTED });
                    ui.painter().line_segment([c + vec2(-4.5, -4.5), c + vec2(4.5, 4.5)], stroke);
                    ui.painter().line_segment([c + vec2(-4.5, 4.5), c + vec2(4.5, -4.5)], stroke);
                    if close.on_hover_text("Close").clicked() {
                        action = Action::Dismiss;
                    }
                    if alert.count > 1 {
                        ui.label(
                            RichText::new(format!("{}/{}", alert.position + 1, alert.count))
                                .small()
                                .color(theme::TEXT_MUTED),
                        );
                    }
                });
            })
            .response;
        let drag = ui.interact(header.rect, egui::Id::new("alert_drag"), Sense::drag());
        if drag.drag_started() {
            ctx.send_viewport_cmd(egui::ViewportCommand::StartDrag);
        }

        ui.add_space(8.0);
        egui::Grid::new("alert_fields")
            .num_columns(2)
            .spacing([12.0, 4.0])
            .min_col_width(70.0)
            .show(ui, |ui| {
                let mut row = |label: &str, value: String| {
                    ui.label(RichText::new(label).color(theme::TEXT_MUTED));
                    ui.add(egui::Label::new(value).truncate());
                    ui.end_row();
                };
                row("File", p.path.clone());
                if let Some(signature) = &alert.signature {
                    let text = match signature {
                        Some(name) if !name.is_empty() => name.clone(),
                        Some(_) => "Valid".into(),
                        None => "Not signed".into(),
                    };
                    row("Signature", text);
                }
                row("Address", if p.remote_addr.is_empty() { "—".into() } else { p.remote_addr.clone() });
                if let Some(host) = &alert.host {
                    row("Host", host.clone());
                }
                row("Port", if p.remote_port == 0 { "—".into() } else { p.remote_port.to_string() });
                row("Protocol", protocol_label(p.protocol).to_string());
                row("Date", shell::format_time(p.time));
            });

        ui.add_space(10.0);
        ui.horizontal(|ui| {
            let allow = egui::Button::new(RichText::new("Allow").color(theme::text_on(alert.accent))).fill(alert.accent);
            if ui.add(allow).on_hover_text("Allow network access for this app").clicked() {
                action = Action::Allow(None);
            }
            ui.menu_button("Allow for…", |ui| {
                for (seconds, label) in TIMERS {
                    if ui.button(label).clicked() {
                        ui.close_menu();
                        action = Action::Allow(Some(seconds));
                    }
                }
            });
            if ui.button("Block").on_hover_text("Keep it blocked and stop notifying").clicked() {
                action = Action::Block;
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if alert.count > 1 && ui.button("Next ›").clicked() {
                    action = Action::Next;
                }
                ui.menu_button("…", |ui| {
                    if ui.button("Create rule…").clicked() {
                        ui.close_menu();
                        action = Action::CreateRule;
                    }
                    if alert.app.kind == crate::model::AppKind::Regular {
                        if ui.button("Open file location").clicked() {
                            ui.close_menu();
                            action = Action::Reveal;
                        }
                        if ui.button("Kill process").clicked() {
                            ui.close_menu();
                            action = Action::Kill;
                        }
                    }
                    ui.separator();
                    if ui.button("Disable notifications for this app").clicked() {
                        ui.close_menu();
                        action = Action::Silence;
                    }
                });
            });
        });
    });
    if ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
        action = Action::Dismiss;
    }
    action
}

fn icon_path(app: &AppItem) -> String {
    let windows = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    match app.kind {
        crate::model::AppKind::Regular => app.path.clone(),
        crate::model::AppKind::System => format!(r"{windows}\system32\ntoskrnl.exe"),
        crate::model::AppKind::Service => format!(r"{windows}\system32\svchost.exe"),
        crate::model::AppKind::Uwp => "app.exe".into(),
    }
}
