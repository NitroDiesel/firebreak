//! Report list in the style of the C build's list views: sortable header,
//! collapsible groups, checkbox + icon rows, highlight fills. Only the visible
//! rows are laid out, so the 1,500-row blocklist costs the same as a short list.

use std::collections::HashMap;
use std::sync::Arc;

use eframe::egui::{
    self, pos2, text::LayoutJob, text::TextWrapping, vec2, Align2, Color32, FontId, Galley, Id,
    Painter, Pos2, Rect, Response, Sense, Shape, Stroke, StrokeKind, TextureHandle, TextureId, Ui,
};

use super::shell;
use super::theme::{self, Icons, ROW_HEIGHT};

const PAD: f32 = 10.0;
const CHECK: f32 = 14.0;
const ICON: f32 = 16.0;
const HEADER_HEIGHT: f32 = 28.0;

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
}

impl List<'_> {
    pub fn show(self, ui: &mut Ui, art: &mut Art) -> Output {
        let mut out = Output::default();
        let full = ui.available_width();
        let widths = column_widths(self.columns, full);
        self.header(ui, &widths, &mut out);

        let body = ui.available_rect_before_wrap();
        ui.painter().rect_filled(body, 0.0, theme::SURFACE);
        if self.lines.is_empty() {
            ui.painter().text(
                body.center_top() + vec2(0.0, 40.0),
                Align2::CENTER_CENTER,
                self.empty,
                FontId::proportional(13.0),
                theme::TEXT_MUTED,
            );
            return out;
        }

        let mut budget = 6u32;
        ui.scope(|ui| {
            ui.spacing_mut().item_spacing.y = 0.0;
            egui::ScrollArea::vertical()
                .id_salt(self.id)
                .auto_shrink(false)
                .show_rows(ui, ROW_HEIGHT, self.lines.len(), |ui, range| {
                    ui.spacing_mut().item_spacing = egui::Vec2::ZERO;
                    let top = ui.max_rect().top();
                    let left = ui.max_rect().left();
                    if let Some(target) = self.scroll_to {
                        let y = top + (target as f32 - range.start as f32) * ROW_HEIGHT;
                        let rect = Rect::from_min_size(pos2(left, y), vec2(1.0, ROW_HEIGHT));
                        ui.scroll_to_rect(rect, None);
                    }
                    for index in range {
                        let (rect, _) = ui.allocate_exact_size(vec2(full, ROW_HEIGHT), Sense::hover());
                        match &self.lines[index] {
                            Line::Group { id, title, collapsed } => {
                                let response = ui.interact(rect, self.id.with(("group", *id)), Sense::click());
                                paint_group(ui.painter(), rect, title, *collapsed, response.hovered());
                                if response.clicked() {
                                    out.group = Some(*id);
                                }
                            }
                            Line::Row(row) => {
                                self.row(ui, rect, row, &widths, art, &mut budget, &mut out);
                            }
                        }
                    }
                });
        });
        out
    }

    fn header(&self, ui: &mut Ui, widths: &[f32], out: &mut Output) {
        let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), HEADER_HEIGHT), Sense::hover());
        let painter = ui.painter();
        painter.rect_filled(rect, 0.0, theme::CHROME);
        painter.hline(rect.x_range(), rect.bottom() - 0.5, Stroke::new(1.0_f32, theme::BORDER));
        let mut x = rect.left();
        for (index, (column, width)) in self.columns.iter().zip(widths).enumerate() {
            let cell = Rect::from_min_size(pos2(x, rect.top()), vec2(*width, rect.height()));
            x += width;
            let response = ui.interact(cell, self.id.with(("head", index)), Sense::click());
            if response.hovered() {
                painter.rect_filled(cell, 0.0, theme::HOVER);
            }
            if response.clicked() {
                out.sort = Some(index);
            }
            let sorted = self.sort.column == index;
            let color = if sorted { theme::TEXT } else { theme::TEXT_MUTED };
            let galley = single_line(painter, column.title, theme::semibold(12.0), color, width - PAD * 2.0 - 12.0);
            let text_x = if column.right {
                cell.right() - PAD - galley.size().x
            } else {
                cell.left() + PAD
            };
            let text_pos = pos2(text_x, cell.center().y - galley.size().y / 2.0);
            let text_width = galley.size().x;
            painter.galley(text_pos, galley, color);
            if sorted {
                let arrow_x = if column.right { text_x - 10.0 } else { text_x + text_width + 6.0 };
                paint_sort_arrow(painter, pos2(arrow_x, cell.center().y), self.sort.descending);
            }
            if index + 1 < self.columns.len() {
                painter.vline(cell.right() - 0.5, cell.top() + 7.0..=cell.bottom() - 7.0, Stroke::new(1.0_f32, theme::BORDER));
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn row(&self, ui: &mut Ui, rect: Rect, row: &Row, widths: &[f32], art: &mut Art, budget: &mut u32, out: &mut Output) {
        let mut response = ui.interact(rect, self.id.with(("row", row.id)), Sense::click());
        let check_rect = Rect::from_center_size(
            pos2(rect.left() + PAD + CHECK / 2.0, rect.center().y),
            vec2(CHECK, CHECK),
        );
        let check_response = row
            .check
            .map(|_| ui.interact(check_rect.expand(4.0), self.id.with(("check", row.id)), Sense::click()));

        let painter = ui.painter();
        let selected = self.selected == Some(row.id);
        let hovered = response.hovered() || check_response.as_ref().is_some_and(|r| r.hovered());
        if let Some(fill) = row.fill {
            painter.rect_filled(rect, 0.0, fill);
            if selected {
                painter.rect_filled(rect, 0.0, Color32::from_black_alpha(36));
                painter.rect_stroke(rect.shrink(0.5), 0.0, Stroke::new(1.5_f32, art.accent), StrokeKind::Inside);
            } else if hovered {
                painter.rect_filled(rect, 0.0, Color32::from_black_alpha(18));
            }
        } else if selected {
            painter.rect_filled(rect, 0.0, art.accent.gamma_multiply(0.30));
            painter.rect_filled(Rect::from_min_size(rect.min, vec2(2.0, rect.height())), 0.0, art.accent);
        } else if hovered {
            painter.rect_filled(rect, 0.0, theme::HOVER);
        }
        let on_fill = row.fill.is_some();
        let text_color = if on_fill { theme::TEXT_ON_FILL } else { theme::TEXT };

        let mut x = rect.left() + PAD;
        if let Some(checked) = row.check {
            paint_check(painter, check_rect, checked, art.accent, on_fill);
            x += CHECK + 8.0;
        }
        let texture = match &row.icon {
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
        };
        if !matches!(row.icon, Icon::None) {
            if let Some(texture) = texture {
                let icon_rect = Rect::from_min_size(pos2(x, rect.center().y - ICON / 2.0), vec2(ICON, ICON));
                let uv = Rect::from_min_max(pos2(0.0, 0.0), pos2(1.0, 1.0));
                painter.image(texture, icon_rect, uv, Color32::WHITE);
            }
            x += ICON + 8.0;
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
            let color = if index == 0 { text_color } else if on_fill { theme::TEXT_ON_FILL } else { theme::TEXT_MUTED };
            let galley = single_line(painter, cell, FontId::proportional(13.0), color, end - start);
            let gx = if column.right { end - galley.size().x } else { start };
            painter.galley(Pos2::new(gx, rect.center().y - galley.size().y / 2.0), galley, color);
        }

        if let Some(check) = check_response {
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
        if let Some(hint) = &row.hint {
            response = response.on_hover_text_at_pointer(hint);
        }
        out.rows.push((row.id, response));
    }
}

/// The fill column gets what is left. In a narrow window the fixed columns
/// shrink together so every column stays on screen.
fn column_widths(columns: &[Column], full: f32) -> Vec<f32> {
    const MIN_FILL: f32 = 140.0;
    let fixed: f32 = columns.iter().map(|c| c.width).sum();
    let scale = if fixed > 0.0 && full - fixed < MIN_FILL {
        ((full - MIN_FILL) / fixed).clamp(0.4, 1.0)
    } else {
        1.0
    };
    let fill = (full - fixed * scale).max(MIN_FILL);
    columns
        .iter()
        .map(|c| if c.width == 0.0 { fill } else { c.width * scale })
        .collect()
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
        let widths = column_widths(&columns, 640.0);
        assert!((widths.iter().sum::<f32>() - 640.0).abs() < 0.5);
        assert!(widths[0] >= 140.0);
        let wide = column_widths(&columns, 1200.0);
        assert_eq!(wide[1], 160.0);
        assert_eq!(wide[0], 1200.0 - 690.0);
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
        let edge = if on_fill { Color32::from_gray(0x60) } else { Color32::from_gray(0x8A) };
        let base = if on_fill { Color32::from_white_alpha(140) } else { Color32::from_gray(0x1F) };
        painter.rect_filled(rect, 3.0, base);
        painter.rect_stroke(rect, 3.0, Stroke::new(1.0_f32, edge), StrokeKind::Inside);
    }
}

fn paint_group(painter: &Painter, rect: Rect, title: &str, collapsed: bool, hovered: bool) {
    if hovered {
        painter.rect_filled(rect, 0.0, theme::HOVER);
    }
    let c = pos2(rect.left() + PAD + 4.0, rect.center().y);
    let points = if collapsed {
        vec![c + vec2(-2.0, -4.0), c + vec2(2.5, 0.0), c + vec2(-2.0, 4.0)]
    } else {
        vec![c + vec2(-4.0, -2.0), c + vec2(4.0, -2.0), c + vec2(0.0, 2.5)]
    };
    painter.add(Shape::convex_polygon(points, theme::TEXT_MUTED, Stroke::NONE));
    let galley = single_line(painter, title, theme::semibold(12.5), theme::TEXT, rect.width() - 60.0);
    let text_pos = pos2(rect.left() + PAD + 16.0, rect.center().y - galley.size().y / 2.0);
    let line_x = text_pos.x + galley.size().x + 10.0;
    painter.galley(text_pos, galley, theme::TEXT);
    if line_x < rect.right() - PAD {
        painter.hline(line_x..=rect.right() - PAD, rect.center().y, Stroke::new(1.0_f32, theme::BORDER));
    }
}

fn paint_sort_arrow(painter: &Painter, center: Pos2, descending: bool) {
    let points = if descending {
        vec![center + vec2(-3.5, -1.5), center + vec2(3.5, -1.5), center + vec2(0.0, 2.5)]
    } else {
        vec![center + vec2(-3.5, 1.5), center + vec2(3.5, 1.5), center + vec2(0.0, -2.5)]
    };
    painter.add(Shape::convex_polygon(points, theme::TEXT_MUTED, Stroke::NONE));
}
