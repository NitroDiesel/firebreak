//! Report list in the style of the C build's list views: sortable header,
//! collapsible groups, checkbox + icon rows, highlight fills. Like the
//! original it has Details, Icon, and Tile views, three icon sizes, hidden
//! icons, and column auto-size. Only the visible part is laid out, so the
//! 1,500-row blocklist costs the same as a short list.

use std::collections::HashMap;
use std::sync::Arc;

use eframe::egui::{
    self, pos2, text::LayoutJob, text::TextWrapping, vec2, Align2, Color32, FontId, Galley, Id, Painter, Pos2, Rect,
    Response, Sense, Shape, Stroke, StrokeKind, TextureHandle, TextureId, Ui,
};

use super::shell;
use super::theme::{self, Icons};

const PAD: f32 = 10.0;
const CHECK: f32 = 14.0;
const HEADER_HEIGHT: f32 = 28.0;
const GROUP_HEIGHT: f32 = 28.0;

pub struct Column {
    pub title: &'static str,
    /// Zero fills the remaining width.
    pub width: f32,
    pub right: bool,
}

pub enum Icon {
    None,
    Allow,
    Block,
    Error,
    /// Shell icon of a file. `generic` asks for the icon of the extension only.
    File { path: String, generic: bool },
}

pub struct Row {
    /// Index into the source list (apps, rules, connections, or packets).
    pub id: usize,
    pub cells: Vec<String>,
    pub check: Option<bool>,
    pub icon: Icon,
    pub fill: Option<Color32>,
    pub hint: Option<String>,
}

pub enum Line {
    Group { id: u8, title: String, collapsed: bool },
    Row(Row),
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Sort {
    pub column: usize,
    pub descending: bool,
}

/// IDM_VIEW_DETAILS, IDM_VIEW_ICON, IDM_VIEW_TILE.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum View {
    Details,
    Icons,
    Tiles,
}

impl View {
    pub fn from_setting(value: u64) -> Self {
        match value {
            1 => Self::Icons,
            2 => Self::Tiles,
            _ => Self::Details,
        }
    }
}

/// How the list looks (the View menu).
#[derive(Clone, Copy)]
pub struct Look<'a> {
    pub view: View,
    /// 16, 32, or 48 (IDM_SIZE_SMALL / LARGE / EXTRALARGE).
    pub icon: f32,
    /// IDM_ICONSISHIDDEN
    pub hide_icons: bool,
    /// Measured widths for fixed columns, with "Autosize columns".
    pub auto_widths: Option<&'a [f32]>,
}

impl Look<'_> {
    fn icon_size(&self) -> f32 {
        if self.hide_icons {
            0.0
        } else {
            self.icon
        }
    }

    /// Height of a Details row.
    fn row_height(&self) -> f32 {
        (self.icon_size() + 8.0).max(theme::px(24.0))
    }
}

#[derive(Default)]
pub struct Output {
    pub sort: Option<usize>,
    pub group: Option<u8>,
    pub clicked: Option<usize>,
    pub toggled: Option<usize>,
    pub activated: Option<usize>,
    /// Visible rows, so the caller can attach context menus.
    pub rows: Vec<(usize, Response)>,
    /// A file icon is still loading; ask for one more frame.
    pub pending_icons: bool,
}

/// Lazily loaded shell icons, a few per frame.
#[derive(Default)]
pub struct FileIcons {
    map: HashMap<String, Option<TextureHandle>>,
}

impl FileIcons {
    pub fn get(&mut self, ctx: &egui::Context, path: &str, generic: bool, budget: &mut u32) -> Option<Option<TextureId>> {
        let key = if generic {
            path.rsplit('.').next().unwrap_or(path).to_ascii_lowercase()
        } else {
            path.to_ascii_lowercase()
        };
        if let Some(hit) = self.map.get(&key) {
            return Some(hit.as_ref().map(|t| t.id()));
        }
        if *budget == 0 {
            return None;
        }
        *budget -= 1;
        let texture = shell::file_icon(path, generic)
            .or_else(|| shell::file_icon("file.exe", true))
            .map(|image| ctx.load_texture(format!("icon:{key}"), image, theme::texture_options()));
        let id = texture.as_ref().map(|t| t.id());
        self.map.insert(key, texture);
        Some(id)
    }
}

pub struct Art<'a> {
    pub icons: &'a Icons,
    pub files: &'a mut FileIcons,
    pub accent: Color32,
}

pub struct List<'a> {
    pub id: Id,
    pub columns: &'a [Column],
    pub lines: &'a [Line],
    pub sort: Sort,
    pub selected: Option<usize>,
    /// Line index to bring into view.
    pub scroll_to: Option<usize>,
    pub empty: &'a str,
    pub look: Look<'a>,
}

/// One painted line of a grid view: a group header, or a run of items.
enum GridLine {
    Group(usize),
    Items(std::ops::Range<usize>),
}

impl List<'_> {
    pub fn show(self, ui: &mut Ui, art: &mut Art) -> Output {
        let mut out = Output::default();
        let full = ui.available_width();
        let widths = column_widths(self.columns, full, self.look.auto_widths);
        if self.look.view == View::Details {
            self.header(ui, &widths, &mut out);
        }

        let body = ui.available_rect_before_wrap();
        ui.painter().rect_filled(body, 0.0, theme::surface());
        if self.lines.is_empty() {
            ui.painter().text(
                body.center_top() + vec2(0.0, 40.0),
                Align2::CENTER_CENTER,
                self.empty,
                theme::body(13.0),
                theme::text_muted(),
            );
            return out;
        }

        let mut budget = 6u32;
        ui.scope(|ui| {
            ui.spacing_mut().item_spacing.y = 0.0;
            match self.look.view {
                View::Details => self.details(ui, full, &widths, art, &mut budget, &mut out),
                View::Icons | View::Tiles => self.grid(ui, full, art, &mut budget, &mut out),
            }
        });
        out
    }

    fn details(&self, ui: &mut Ui, full: f32, widths: &[f32], art: &mut Art, budget: &mut u32, out: &mut Output) {
        let height = self.look.row_height();
        egui::ScrollArea::vertical()
            .id_salt(self.id)
            .auto_shrink(false)
            .show_rows(ui, height, self.lines.len(), |ui, range| {
                ui.spacing_mut().item_spacing = egui::Vec2::ZERO;
                let top = ui.max_rect().top();
                let left = ui.max_rect().left();
                if let Some(target) = self.scroll_to {
                    let y = top + (target as f32 - range.start as f32) * height;
                    ui.scroll_to_rect(Rect::from_min_size(pos2(left, y), vec2(1.0, height)), None);
                }
                for index in range {
                    let (rect, _) = ui.allocate_exact_size(vec2(full, height), Sense::hover());
                    match &self.lines[index] {
                        Line::Group { id, title, collapsed } => self.group(ui, rect, *id, title, *collapsed, out),
                        Line::Row(row) => self.row(ui, rect, row, widths, art, budget, out),
                    }
                }
            });
    }

    /// Icon and Tile views: items flow left to right under their group header.
    fn grid(&self, ui: &mut Ui, full: f32, art: &mut Art, budget: &mut u32, out: &mut Output) {
        let icon = self.look.icon_size();
        let (cell_w, cell_h) = match self.look.view {
            View::Icons => ((icon + 56.0).max(96.0), icon + 48.0),
            _ => (260.0, (icon + 16.0).max(52.0)),
        };
        let per_line = ((full - PAD) / cell_w).floor().max(1.0) as usize;
        // Group headers break the flow, so items are chunked between them.
        let mut lines = Vec::new();
        let mut run_start = None;
        for (index, line) in self.lines.iter().enumerate() {
            match line {
                Line::Group { .. } => {
                    if let Some(start) = run_start.take() {
                        push_runs(&mut lines, start, index, per_line);
                    }
                    lines.push(GridLine::Group(index));
                }
                Line::Row(_) => {
                    run_start.get_or_insert(index);
                }
            }
        }
        if let Some(start) = run_start {
            push_runs(&mut lines, start, self.lines.len(), per_line);
        }
        let heights: Vec<f32> = lines
            .iter()
            .map(|l| if matches!(l, GridLine::Group(_)) { GROUP_HEIGHT } else { cell_h })
            .collect();
        let total: f32 = heights.iter().sum();
        egui::ScrollArea::vertical().id_salt(self.id).auto_shrink(false).show_viewport(ui, |ui, viewport| {
            ui.set_height(total);
            ui.spacing_mut().item_spacing = egui::Vec2::ZERO;
            let origin = ui.max_rect().min;
            let mut y = 0.0;
            for (line, height) in lines.iter().zip(&heights) {
                let top = y;
                y += height;
                let wanted = self.scroll_to.is_some_and(|target| match line {
                    GridLine::Group(index) => *index == target,
                    GridLine::Items(range) => range.contains(&target),
                });
                let rect = Rect::from_min_size(origin + vec2(0.0, top), vec2(full, *height));
                if wanted {
                    ui.scroll_to_rect(rect, None);
                }
                if y < viewport.min.y || top > viewport.max.y {
                    continue;
                }
                match line {
                    GridLine::Group(index) => {
                        if let Line::Group { id, title, collapsed } = &self.lines[*index] {
                            self.group(ui, rect, *id, title, *collapsed, out);
                        }
                    }
                    GridLine::Items(range) => {
                        for (slot, index) in range.clone().enumerate() {
                            if let Line::Row(row) = &self.lines[index] {
                                let cell = Rect::from_min_size(
                                    rect.min + vec2(PAD / 2.0 + slot as f32 * cell_w, 0.0),
                                    vec2(cell_w, cell_h),
                                )
                                .shrink(3.0);
                                self.tile(ui, cell, row, art, budget, out);
                            }
                        }
                    }
                }
            }
        });
    }

    fn group(&self, ui: &mut Ui, rect: Rect, id: u8, title: &str, collapsed: bool, out: &mut Output) {
        let response = ui.interact(rect, self.id.with(("group", id)), Sense::click());
        paint_group(ui.painter(), rect, title, collapsed, response.hovered());
        if response.clicked() {
            out.group = Some(id);
        }
    }

    fn header(&self, ui: &mut Ui, widths: &[f32], out: &mut Output) {
        let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), HEADER_HEIGHT), Sense::hover());
        let painter = ui.painter();
        painter.rect_filled(rect, 0.0, theme::chrome());
        painter.hline(rect.x_range(), rect.bottom() - 0.5, Stroke::new(1.0_f32, theme::border()));
        let mut x = rect.left();
        for (index, (column, width)) in self.columns.iter().zip(widths).enumerate() {
            let cell = Rect::from_min_size(pos2(x, rect.top()), vec2(*width, rect.height()));
            x += width;
            let response = ui.interact(cell, self.id.with(("head", index)), Sense::click());
            if response.hovered() {
                painter.rect_filled(cell, 0.0, theme::hover());
            }
            if response.clicked() {
                out.sort = Some(index);
            }
            let sorted = self.sort.column == index;
            let color = if sorted { theme::text() } else { theme::text_muted() };
            let galley = single_line(painter, crate::i18n::t(column.title), theme::semibold(12.0), color, width - PAD * 2.0 - ARROW_ROOM);
            let text_x = if column.right {
                cell.right() - PAD - galley.size().x
            } else {
                cell.left() + PAD
            };
            let text_pos = pos2(text_x, cell.center().y - galley.size().y / 2.0);
            let text_width = galley.size().x;
            painter.galley(text_pos, galley, color);
            if sorted {
                let offset = ARROW_ROOM - 3.5;
                let arrow_x = if column.right { text_x - offset } else { text_x + text_width + offset };
                paint_sort_arrow(painter, pos2(arrow_x, cell.center().y), self.sort.descending);
            }
            if index + 1 < self.columns.len() {
                painter.vline(cell.right() - 0.5, cell.top() + 7.0..=cell.bottom() - 7.0, Stroke::new(1.0_f32, theme::border()));
            }
        }
    }

    fn texture(&self, ui: &Ui, row: &Row, art: &mut Art, budget: &mut u32, out: &mut Output) -> Option<TextureId> {
        if self.look.hide_icons {
            return None;
        }
        match &row.icon {
            Icon::None => None,
            Icon::Allow => Some(art.icons.allow.id()),
            Icon::Block => Some(art.icons.block.id()),
            Icon::Error => Some(art.icons.error.id()),
            Icon::File { path, generic } => match art.files.get(ui.ctx(), path, *generic, budget) {
                Some(id) => id,
                None => {
                    out.pending_icons = true;
                    None
                }
            },
        }
    }

    /// Fill, hover, and selection behind a row or tile; returns the text color.
    fn paint_background(&self, painter: &Painter, rect: Rect, row: &Row, hovered: bool, accent: Color32, radius: f32) -> Color32 {
        let selected = self.selected == Some(row.id);
        if let Some(fill) = row.fill {
            painter.rect_filled(rect, radius, fill);
            if selected {
                painter.rect_filled(rect, radius, Color32::from_black_alpha(36));
                painter.rect_stroke(rect.shrink(0.5), radius, Stroke::new(1.5_f32, accent), StrokeKind::Inside);
            } else if hovered {
                painter.rect_filled(rect, radius, Color32::from_black_alpha(18));
            }
            theme::TEXT_ON_FILL
        } else {
            if selected {
                painter.rect_filled(rect, radius, accent.gamma_multiply(0.30));
                if radius == 0.0 {
                    painter.rect_filled(Rect::from_min_size(rect.min, vec2(2.0, rect.height())), 0.0, accent);
                }
            } else if hovered {
                painter.rect_filled(rect, radius, theme::hover());
            }
            theme::text()
        }
    }

    fn respond(&self, response: Response, check: Option<Response>, row: &Row, out: &mut Output) {
        if let Some(check) = check {
            if check.clicked() {
                out.toggled = Some(row.id);
            }
        }
        if response.clicked() || response.secondary_clicked() {
            out.clicked = Some(row.id);
        }
        if response.double_clicked() {
            out.activated = Some(row.id);
        }
        let response = match &row.hint {
            Some(hint) => response.on_hover_text_at_pointer(hint),
            None => response,
        };
        out.rows.push((row.id, response));
    }

    #[allow(clippy::too_many_arguments)]
    fn row(&self, ui: &mut Ui, rect: Rect, row: &Row, widths: &[f32], art: &mut Art, budget: &mut u32, out: &mut Output) {
        let response = ui.interact(rect, self.id.with(("row", row.id)), Sense::click());
        let check_rect = Rect::from_center_size(pos2(rect.left() + PAD + CHECK / 2.0, rect.center().y), vec2(CHECK, CHECK));
        let check = row
            .check
            .map(|_| ui.interact(check_rect.expand(4.0), self.id.with(("check", row.id)), Sense::click()));
        let hovered = response.hovered() || check.as_ref().is_some_and(|r| r.hovered());
        let texture = self.texture(ui, row, art, budget, out);
        let painter = ui.painter();
        let text_color = self.paint_background(painter, rect, row, hovered, art.accent, 0.0);
        let on_fill = row.fill.is_some();

        let mut x = rect.left() + PAD;
        if let Some(checked) = row.check {
            paint_check(painter, check_rect, checked, art.accent, on_fill);
            x += CHECK + 8.0;
        }
        let icon = self.look.icon_size();
        if icon > 0.0 && !matches!(row.icon, Icon::None) {
            if let Some(texture) = texture {
                let icon_rect = Rect::from_min_size(pos2(x, rect.center().y - icon / 2.0), vec2(icon, icon));
                painter.image(texture, icon_rect, full_uv(), Color32::WHITE);
            }
            x += icon + 8.0;
        }

        let mut cell_left = rect.left();
        for (index, (cell, width)) in row.cells.iter().zip(widths).enumerate() {
            let column = &self.columns[index];
            let start = if index == 0 { x } else { cell_left + PAD };
            let end = cell_left + width - PAD;
            cell_left += width;
            if end <= start || cell.is_empty() {
                continue;
            }
            let color = if index == 0 { text_color } else if on_fill { theme::TEXT_ON_FILL } else { theme::text_muted() };
            let galley = single_line(painter, cell, theme::body(13.0), color, end - start);
            let gx = if column.right { end - galley.size().x } else { start };
            painter.galley(Pos2::new(gx, rect.center().y - galley.size().y / 2.0), galley, color);
        }
        self.respond(response, check, row, out);
    }

    /// One item in the Icon or Tile view.
    fn tile(&self, ui: &mut Ui, rect: Rect, row: &Row, art: &mut Art, budget: &mut u32, out: &mut Output) {
        let response = ui.interact(rect, self.id.with(("row", row.id)), Sense::click());
        let check_rect = Rect::from_min_size(rect.min + vec2(6.0, 6.0), vec2(CHECK, CHECK));
        let check = row
            .check
            .map(|_| ui.interact(check_rect.expand(4.0), self.id.with(("check", row.id)), Sense::click()));
        let hovered = response.hovered() || check.as_ref().is_some_and(|r| r.hovered());
        let texture = self.texture(ui, row, art, budget, out);
        let painter = ui.painter();
        let text_color = self.paint_background(painter, rect, row, hovered, art.accent, 6.0);
        let on_fill = row.fill.is_some();
        let muted = if on_fill { theme::TEXT_ON_FILL } else { theme::text_muted() };
        let icon = self.look.icon_size();
        let name = row.cells.first().map(String::as_str).unwrap_or("");
        let detail = row.cells.iter().skip(1).filter(|c| !c.is_empty()).cloned().collect::<Vec<_>>().join(" · ");
        match self.look.view {
            View::Icons => {
                if let Some(texture) = texture.filter(|_| icon > 0.0) {
                    let icon_rect = Rect::from_center_size(pos2(rect.center().x, rect.top() + 8.0 + icon / 2.0), vec2(icon, icon));
                    painter.image(texture, icon_rect, full_uv(), Color32::WHITE);
                }
                let galley = single_line(painter, name, theme::body(12.5), text_color, rect.width() - 8.0);
                let pos = pos2(rect.center().x - galley.size().x / 2.0, rect.bottom() - 8.0 - galley.size().y);
                painter.galley(pos, galley, text_color);
            }
            _ => {
                let mut x = rect.left() + 8.0 + if row.check.is_some() { CHECK + 8.0 } else { 0.0 };
                if let Some(texture) = texture.filter(|_| icon > 0.0) {
                    let icon_rect = Rect::from_min_size(pos2(x, rect.center().y - icon / 2.0), vec2(icon, icon));
                    painter.image(texture, icon_rect, full_uv(), Color32::WHITE);
                    x += icon + 8.0;
                }
                let width = rect.right() - 8.0 - x;
                let title = single_line(painter, name, theme::semibold(13.0), text_color, width);
                let sub = single_line(painter, &detail, theme::body(11.5), muted, width);
                let block = title.size().y + 2.0 + sub.size().y;
                let y = rect.center().y - block / 2.0;
                let title_height = title.size().y;
                painter.galley(pos2(x, y), title, text_color);
                painter.galley(pos2(x, y + title_height + 2.0), sub, muted);
            }
        }
        if let Some(checked) = row.check {
            let check_rect = if self.look.view == View::Tiles {
                Rect::from_center_size(pos2(rect.left() + 8.0 + CHECK / 2.0, rect.center().y), vec2(CHECK, CHECK))
            } else {
                check_rect
            };
            paint_check(painter, check_rect, checked, art.accent, on_fill);
        }
        self.respond(response, check, row, out);
    }
}

fn push_runs(lines: &mut Vec<GridLine>, start: usize, end: usize, per_line: usize) {
    let mut at = start;
    while at < end {
        let next = (at + per_line).min(end);
        lines.push(GridLine::Items(at..next));
        at = next;
    }
}

fn full_uv() -> Rect {
    Rect::from_min_max(pos2(0.0, 0.0), pos2(1.0, 1.0))
}

/// The fill column gets what is left. In a narrow window the wide fixed
/// columns (addresses, hosts) give up their width first, so short ones such as
/// State or Total stay readable; only if that is not enough does every column
/// shrink. `auto` replaces the fixed widths with measured ones (Autosize columns).
fn column_widths(columns: &[Column], full: f32, auto: Option<&[f32]>) -> Vec<f32> {
    const MIN_FILL: f32 = 140.0;
    /// Width a column keeps before any column is shrunk below its own width.
    const KEEP: f32 = 96.0;
    let base: Vec<f32> = columns
        .iter()
        .enumerate()
        .map(|(i, c)| match auto.and_then(|a| a.get(i)) {
            Some(w) if c.width != 0.0 => *w,
            _ => c.width,
        })
        .collect();
    let fixed: f32 = base.iter().sum();
    let budget = full - MIN_FILL;
    let kept: f32 = base.iter().map(|w| w.min(KEEP)).sum();
    let widths: Vec<f32> = if fixed <= budget {
        base.clone()
    } else if kept <= budget {
        let ratio = (budget - kept) / (fixed - kept);
        base.iter().map(|w| w.min(KEEP) + (w - w.min(KEEP)) * ratio).collect()
    } else {
        let scale = (budget / fixed).clamp(0.4, 1.0);
        base.iter().map(|w| w * scale).collect()
    };
    let fill = (full - widths.iter().sum::<f32>()).max(MIN_FILL);
    base.iter().zip(widths).map(|(b, w)| if *b == 0.0 { fill } else { w }).collect()
}

/// Width each fixed column needs for its title and every cell (Autosize columns).
pub fn measure_columns(ctx: &egui::Context, columns: &[Column], lines: &[Line]) -> Vec<f32> {
    ctx.fonts(|fonts| {
        let width = |text: &str, font: FontId| fonts.layout_no_wrap(text.to_owned(), font, Color32::WHITE).size().x;
        columns
            .iter()
            .enumerate()
            .map(|(i, column)| {
                if column.width == 0.0 {
                    return 0.0;
                }
                let mut widest = width(crate::i18n::t(column.title), theme::semibold(12.0)) + ARROW_ROOM;
                for line in lines {
                    if let Line::Row(row) = line {
                        if let Some(cell) = row.cells.get(i) {
                            widest = widest.max(width(cell, theme::body(13.0)));
                        }
                    }
                }
                (widest + PAD * 2.0).clamp(48.0, 480.0)
            })
            .collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn col(width: f32) -> Column {
        Column { title: "", width, right: false }
    }

    #[test]
    fn narrow_lists_keep_every_column_on_screen() {
        let columns = [col(0.0), col(160.0), col(180.0), col(180.0), col(80.0), col(90.0)];
        let widths = column_widths(&columns, 640.0, None);
        assert!((widths.iter().sum::<f32>() - 640.0).abs() < 0.5);
        assert!(widths[0] >= 140.0);
        let wide = column_widths(&columns, 1200.0, None);
        assert_eq!(wide[1], 160.0);
        assert_eq!(wide[0], 1200.0 - 690.0);
    }

    #[test]
    fn autosize_replaces_fixed_widths_only() {
        let columns = [col(0.0), col(160.0), col(80.0)];
        let widths = column_widths(&columns, 1000.0, Some(&[0.0, 60.0, 70.0]));
        assert_eq!(&widths[1..], &[60.0, 70.0]);
        assert_eq!(widths[0], 1000.0 - 130.0);
    }

    #[test]
    fn narrow_lists_shrink_wide_columns_first() {
        // Connections with traffic: long IPv6 addresses next to short numbers.
        let columns = [col(0.0), col(1.0), col(1.0), col(1.0), col(1.0), col(1.0), col(1.0)];
        let auto = [0.0, 320.0, 320.0, 250.0, 60.0, 90.0, 80.0];
        let widths = column_widths(&columns, 1000.0, Some(&auto));
        assert!((widths.iter().sum::<f32>() - 1000.0).abs() < 0.5);
        assert_eq!(&widths[4..], &[60.0, 90.0, 80.0]);
        assert!(widths[1] < 320.0 && widths[1] > 96.0);
    }

    #[test]
    fn grid_runs_break_at_the_line_width() {
        let mut lines = Vec::new();
        push_runs(&mut lines, 2, 9, 3);
        let runs: Vec<_> = lines
            .iter()
            .map(|l| match l {
                GridLine::Items(r) => r.clone(),
                GridLine::Group(_) => unreachable!(),
            })
            .collect();
        assert_eq!(runs, vec![2..5, 5..8, 8..9]);
    }
}

fn single_line(painter: &Painter, text: &str, font: FontId, color: Color32, width: f32) -> Arc<Galley> {
    let mut job = LayoutJob::simple_singleline(text.to_owned(), font, color);
    job.wrap = TextWrapping::truncate_at_width(width.max(1.0));
    painter.layout_job(job)
}

fn paint_check(painter: &Painter, rect: Rect, checked: bool, accent: Color32, on_fill: bool) {
    if checked {
        painter.rect_filled(rect, 3.0, accent);
        let mark = theme::text_on(accent);
        let at = |x: f32, y: f32| pos2(rect.left() + rect.width() * x, rect.top() + rect.height() * y);
        painter.add(Shape::line(
            vec![at(0.24, 0.52), at(0.42, 0.70), at(0.77, 0.31)],
            Stroke::new(1.7_f32, mark),
        ));
    } else {
        let (well, well_edge) = theme::check_well();
        let edge = if on_fill { Color32::from_gray(0x60) } else { well_edge };
        let base = if on_fill { Color32::from_white_alpha(140) } else { well };
        painter.rect_filled(rect, 3.0, base);
        painter.rect_stroke(rect, 3.0, Stroke::new(1.0_f32, edge), StrokeKind::Inside);
    }
}

fn paint_group(painter: &Painter, rect: Rect, title: &str, collapsed: bool, hovered: bool) {
    if hovered {
        painter.rect_filled(rect, 0.0, theme::hover());
    }
    let c = pos2(rect.left() + PAD + 4.0, rect.center().y);
    let points = if collapsed {
        vec![c + vec2(-2.0, -4.0), c + vec2(2.5, 0.0), c + vec2(-2.0, 4.0)]
    } else {
        vec![c + vec2(-4.0, -2.0), c + vec2(4.0, -2.0), c + vec2(0.0, 2.5)]
    };
    painter.add(Shape::convex_polygon(points, theme::text_muted(), Stroke::NONE));
    let galley = single_line(painter, title, theme::semibold(12.5), theme::text(), rect.width() - 60.0);
    let text_pos = pos2(rect.left() + PAD + 16.0, rect.center().y - galley.size().y / 2.0);
    let line_x = text_pos.x + galley.size().x + 10.0;
    painter.galley(text_pos, galley, theme::text());
    if line_x < rect.right() - PAD {
        painter.hline(line_x..=rect.right() - PAD, rect.center().y, Stroke::new(1.0_f32, theme::border()));
    }
}

/// Room beside a header title for the sort arrow: a gap, then the 7 px arrow.
const ARROW_ROOM: f32 = 15.0;

fn paint_sort_arrow(painter: &Painter, center: Pos2, descending: bool) {
    let points = if descending {
        vec![center + vec2(-3.5, -1.5), center + vec2(3.5, -1.5), center + vec2(0.0, 2.5)]
    } else {
        vec![center + vec2(-3.5, 1.5), center + vec2(3.5, 1.5), center + vec2(0.0, -2.5)]
    };
    painter.add(Shape::convex_polygon(points, theme::text_muted(), Stroke::NONE));
}
