//! Palette, fonts, and bundled icons. One accent (the Windows accent color),
//! one neutral gray family, and the original list highlight colors.

use std::sync::Arc;

use eframe::egui::{
    self, Color32, CornerRadius, FontData, FontDefinitions, FontFamily, FontId, Shadow, Stroke,
    TextStyle, TextureHandle, TextureOptions, Vec2,
};

/// Menu bar, toolbar, tabs, and status bar.
pub const CHROME: Color32 = Color32::from_rgb(0x20, 0x20, 0x20);
/// List body.
pub const SURFACE: Color32 = Color32::from_rgb(0x19, 0x19, 0x19);
/// Dialogs and popups.
pub const RAISED: Color32 = Color32::from_rgb(0x2B, 0x2B, 0x2B);
pub const BORDER: Color32 = Color32::from_rgb(0x33, 0x33, 0x33);
pub const TEXT: Color32 = Color32::from_rgb(0xE6, 0xE6, 0xE6);
pub const TEXT_MUTED: Color32 = Color32::from_rgb(0x9D, 0x9D, 0x9D);
/// Text on a highlighted (pastel) row.
pub const TEXT_ON_FILL: Color32 = Color32::from_rgb(0x1A, 0x1A, 0x1A);
pub const HOVER: Color32 = Color32::from_rgba_premultiplied(0x10, 0x10, 0x10, 0x10);
pub const DANGER: Color32 = Color32::from_rgb(0xFF, 0x7C, 0x94);

/// Row highlights, same values as `LV_COLOR_*` in the C build.
pub const FILL_INVALID: Color32 = Color32::from_rgb(0xFF, 0x7C, 0x94);
pub const FILL_SPECIAL: Color32 = Color32::from_rgb(0xFF, 0xFF, 0xAA);
pub const FILL_SIGNED: Color32 = Color32::from_rgb(0xAE, 0xE4, 0xA2);
pub const FILL_CONNECTION: Color32 = Color32::from_rgb(0xFF, 0xA8, 0xF2);
pub const FILL_SYSTEM: Color32 = Color32::from_rgb(0x96, 0xC4, 0xFA);
pub const FILL_UNDELETE: Color32 = Color32::from_rgb(0xD4, 0xD4, 0xD4);

pub const ROW_HEIGHT: f32 = 24.0;
pub const SEMIBOLD: &str = "semibold";

/// Windows accent from `HKCU\Software\Microsoft\Windows\DWM\AccentColor`, or a blue default.
pub fn accent() -> Color32 {
    super::shell::accent_color().unwrap_or(Color32::from_rgb(0x4C, 0xC2, 0xFF))
}

/// Black or white, whichever reads better on `fill`.
pub fn text_on(fill: Color32) -> Color32 {
    let [r, g, b, _] = fill.to_array();
    let luma = 0.2126 * r as f32 + 0.7152 * g as f32 + 0.0722 * b as f32;
    if luma > 150.0 {
        TEXT_ON_FILL
    } else {
        Color32::WHITE
    }
}

pub fn semibold(size: f32) -> FontId {
    FontId::new(size, FontFamily::Name(SEMIBOLD.into()))
}

pub fn apply(ctx: &egui::Context, accent: Color32) {
    install_fonts(ctx);

    let mut visuals = egui::Visuals::dark();
    visuals.panel_fill = CHROME;
    visuals.window_fill = RAISED;
    visuals.extreme_bg_color = SURFACE;
    visuals.faint_bg_color = Color32::from_rgb(0x1E, 0x1E, 0x1E);
    visuals.code_bg_color = SURFACE;
    visuals.hyperlink_color = accent;
    visuals.selection.bg_fill = accent.gamma_multiply(0.45);
    visuals.selection.stroke = Stroke::new(1.0_f32, TEXT);
    visuals.window_stroke = Stroke::new(1.0_f32, BORDER);
    visuals.window_corner_radius = CornerRadius::same(8);
    visuals.menu_corner_radius = CornerRadius::same(6);
    let shadow = Shadow {
        offset: [0, 4],
        blur: 16,
        spread: 0,
        color: Color32::from_black_alpha(110),
    };
    visuals.window_shadow = shadow;
    visuals.popup_shadow = shadow;
    visuals.indent_has_left_vline = false;
    visuals.text_cursor.stroke = Stroke::new(1.5_f32, accent);

    let widgets = &mut visuals.widgets;
    widgets.noninteractive.bg_fill = CHROME;
    widgets.noninteractive.weak_bg_fill = CHROME;
    widgets.noninteractive.bg_stroke = Stroke::new(1.0_f32, BORDER);
    widgets.noninteractive.fg_stroke = Stroke::new(1.0_f32, TEXT);
    for (state, fill) in [
        (&mut widgets.inactive, Color32::from_rgb(0x2D, 0x2D, 0x2D)),
        (&mut widgets.hovered, Color32::from_rgb(0x37, 0x37, 0x37)),
        (&mut widgets.active, Color32::from_rgb(0x41, 0x41, 0x41)),
        (&mut widgets.open, Color32::from_rgb(0x37, 0x37, 0x37)),
    ] {
        state.bg_fill = fill;
        state.weak_bg_fill = fill;
        state.corner_radius = CornerRadius::same(4);
        state.expansion = 0.0;
    }
    // bg_fill is the checkbox and radio well; weak_bg_fill stays the button face.
    widgets.inactive.bg_fill = Color32::from_rgb(0x3A, 0x3A, 0x3A);
    widgets.hovered.bg_fill = Color32::from_rgb(0x45, 0x45, 0x45);
    widgets.inactive.bg_stroke = Stroke::new(1.0_f32, Color32::from_rgb(0x55, 0x55, 0x55));
    widgets.inactive.fg_stroke = Stroke::new(1.0_f32, TEXT);
    widgets.hovered.bg_stroke = Stroke::new(1.0_f32, Color32::from_rgb(0x4A, 0x4A, 0x4A));
    widgets.hovered.fg_stroke = Stroke::new(1.0_f32, Color32::WHITE);
    widgets.active.bg_stroke = Stroke::new(1.0_f32, accent);
    widgets.active.fg_stroke = Stroke::new(1.0_f32, Color32::WHITE);
    widgets.open.bg_stroke = Stroke::new(1.0_f32, BORDER);
    widgets.open.fg_stroke = Stroke::new(1.0_f32, TEXT);
    ctx.set_visuals(visuals);

    ctx.style_mut(|style| {
        style.text_styles = [
            (TextStyle::Small, FontId::proportional(11.0)),
            (TextStyle::Body, FontId::proportional(13.0)),
            (TextStyle::Button, FontId::proportional(13.0)),
            (TextStyle::Heading, semibold(17.0)),
            (TextStyle::Monospace, FontId::monospace(12.5)),
        ]
        .into();
        style.spacing.item_spacing = Vec2::new(8.0, 6.0);
        style.spacing.button_padding = Vec2::new(10.0, 4.0);
        style.spacing.interact_size.y = 26.0;
        style.spacing.menu_margin = egui::Margin::same(6);
        style.spacing.window_margin = egui::Margin::same(16);
        style.spacing.scroll.floating = true;
        style.spacing.scroll.bar_width = 8.0;
        style.interaction.selectable_labels = false;
        style.interaction.tooltip_delay = 0.4;
    });
}

/// Segoe UI from the system font folder, with egui's bundled font as fallback.
fn install_fonts(ctx: &egui::Context) {
    let mut fonts = FontDefinitions::default();
    let dir = std::path::PathBuf::from(std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into()))
        .join("Fonts");
    let fallback = fonts.families[&FontFamily::Proportional].clone();
    let mut regular = fallback.clone();
    if let Ok(bytes) = std::fs::read(dir.join("segoeui.ttf")) {
        fonts.font_data.insert("segoe".into(), Arc::new(FontData::from_owned(bytes)));
        regular.insert(0, "segoe".into());
    }
    let mut bold = regular.clone();
    if let Ok(bytes) = std::fs::read(dir.join("seguisb.ttf")) {
        fonts.font_data.insert("segoe-sb".into(), Arc::new(FontData::from_owned(bytes)));
        bold.insert(0, "segoe-sb".into());
    }
    fonts.families.insert(FontFamily::Proportional, regular);
    fonts.families.insert(FontFamily::Name(SEMIBOLD.into()), bold);
    ctx.set_fonts(fonts);
}

/// Toolbar and row icons from `src/res` of the C build, decoded once at startup.
pub struct Icons {
    pub shield_on: TextureHandle,
    pub shield_off: TextureHandle,
    pub plus: TextureHandle,
    pub note: TextureHandle,
    pub refresh: TextureHandle,
    pub settings: TextureHandle,
    pub log_show: TextureHandle,
    pub log_clear: TextureHandle,
    pub search: TextureHandle,
    pub allow: TextureHandle,
    pub block: TextureHandle,
    pub error: TextureHandle,
    pub eye: TextureHandle,
    pub logo: TextureHandle,
}

impl Icons {
    pub fn load(ctx: &egui::Context) -> Self {
        let load = |name: &str, bytes: &[u8]| texture(ctx, name, bytes);
        Self {
            shield_on: load("tick_shield", include_bytes!("../../resources/icons/tick_shield.png")),
            shield_off: load("cross_shield", include_bytes!("../../resources/icons/cross_shield.png")),
            plus: load("plus", include_bytes!("../../resources/icons/plus.png")),
            note: load("note", include_bytes!("../../resources/icons/note.png")),
            refresh: load("refresh", include_bytes!("../../resources/icons/arrow_refresh.png")),
            settings: load("settings", include_bytes!("../../resources/icons/cog_edit.png")),
            log_show: load("log_show", include_bytes!("../../resources/icons/page_white_magnify.png")),
            log_clear: load("log_clear", include_bytes!("../../resources/icons/page_white_delete.png")),
            search: load("search", include_bytes!("../../resources/icons/search.png")),
            allow: load("allow", include_bytes!("../../resources/icons/accept_button.png")),
            block: load("block", include_bytes!("../../resources/icons/cross.png")),
            error: load("error", include_bytes!("../../resources/icons/error.png")),
            eye: load("eye", include_bytes!("../../resources/icons/eye.png")),
            logo: load("logo", include_bytes!("../../resources/icons/simplewall.png")),
        }
    }
}

/// Mipmapped so the 32px sources stay sharp at 16px and at any DPI.
pub fn texture_options() -> TextureOptions {
    TextureOptions {
        mipmap_mode: Some(egui::TextureFilter::Linear),
        ..TextureOptions::LINEAR
    }
}

fn texture(ctx: &egui::Context, name: &str, bytes: &[u8]) -> TextureHandle {
    let image = image::load_from_memory_with_format(bytes, image::ImageFormat::Png)
        .map(|image| image.to_rgba8())
        .unwrap_or_else(|_| image::RgbaImage::new(1, 1));
    let size = [image.width() as usize, image.height() as usize];
    let color = egui::ColorImage::from_rgba_unmultiplied(size, image.as_raw());
    ctx.load_texture(name, color, texture_options())
}
