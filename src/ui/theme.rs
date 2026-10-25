//! Palette, fonts, and bundled icons. One accent (the Windows accent color),
//! one neutral gray family in a dark and a light version, and the original
//! list highlight colors, which are the same in both.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use eframe::egui::{
    self, Color32, CornerRadius, FontData, FontDefinitions, FontFamily, FontId, Shadow, Stroke,
    TextStyle, TextureHandle, TextureOptions, Vec2,
};

/// The neutral colors of one theme.
struct Palette {
    /// Menu bar, toolbar, tabs, and status bar.
    chrome: Color32,
    /// List body.
    surface: Color32,
    /// Dialogs and popups.
    raised: Color32,
    border: Color32,
    text: Color32,
    text_muted: Color32,
    danger: Color32,
    /// Button faces: rest, hover, pressed.
    faces: [Color32; 3],
    /// Checkbox and radio wells: rest, hover.
    wells: [Color32; 2],
    well_edge: Color32,
}

const DARK: Palette = Palette {
    chrome: Color32::from_rgb(0x20, 0x20, 0x20),
    surface: Color32::from_rgb(0x19, 0x19, 0x19),
    raised: Color32::from_rgb(0x2B, 0x2B, 0x2B),
    border: Color32::from_rgb(0x33, 0x33, 0x33),
    text: Color32::from_rgb(0xE6, 0xE6, 0xE6),
    text_muted: Color32::from_rgb(0x9D, 0x9D, 0x9D),
    danger: Color32::from_rgb(0xFF, 0x7C, 0x94),
    faces: [
        Color32::from_rgb(0x2D, 0x2D, 0x2D),
        Color32::from_rgb(0x37, 0x37, 0x37),
        Color32::from_rgb(0x41, 0x41, 0x41),
    ],
    wells: [Color32::from_rgb(0x3A, 0x3A, 0x3A), Color32::from_rgb(0x45, 0x45, 0x45)],
    well_edge: Color32::from_rgb(0x55, 0x55, 0x55),
};

const LIGHT: Palette = Palette {
    chrome: Color32::from_rgb(0xF3, 0xF3, 0xF3),
    surface: Color32::from_rgb(0xFF, 0xFF, 0xFF),
    raised: Color32::from_rgb(0xFB, 0xFB, 0xFB),
    border: Color32::from_rgb(0xE0, 0xE0, 0xE0),
    text: Color32::from_rgb(0x1B, 0x1B, 0x1B),
    text_muted: Color32::from_rgb(0x5F, 0x5F, 0x5F),
    danger: Color32::from_rgb(0xC4, 0x2B, 0x1C),
    faces: [
        Color32::from_rgb(0xFB, 0xFB, 0xFB),
        Color32::from_rgb(0xF0, 0xF0, 0xF0),
        Color32::from_rgb(0xE6, 0xE6, 0xE6),
    ],
    wells: [Color32::from_rgb(0xFF, 0xFF, 0xFF), Color32::from_rgb(0xF3, 0xF3, 0xF3)],
    well_edge: Color32::from_rgb(0x8A, 0x8A, 0x8A),
};

static IS_DARK: AtomicBool = AtomicBool::new(true);

fn palette() -> &'static Palette {
    if IS_DARK.load(Ordering::Relaxed) {
        &DARK
    } else {
        &LIGHT
    }
}

pub fn is_dark() -> bool {
    IS_DARK.load(Ordering::Relaxed)
}

pub fn chrome() -> Color32 {
    palette().chrome
}
pub fn surface() -> Color32 {
    palette().surface
}
pub fn raised() -> Color32 {
    palette().raised
}
pub fn border() -> Color32 {
    palette().border
}
pub fn text() -> Color32 {
    palette().text
}
pub fn text_muted() -> Color32 {
    palette().text_muted
}
pub fn danger() -> Color32 {
    palette().danger
}
/// Hover wash over chrome or the list.
pub fn hover() -> Color32 {
    overlay(1.0)
}

/// A wash that darkens light surfaces and lightens dark ones; `strength` 1.0
/// is the list hover.
pub fn overlay(strength: f32) -> Color32 {
    if is_dark() {
        Color32::from_white_alpha((16.0 * strength).clamp(0.0, 255.0) as u8)
    } else {
        Color32::from_black_alpha((12.0 * strength).clamp(0.0, 255.0) as u8)
    }
}

/// Unchecked checkbox in a list row: (well, edge).
pub fn check_well() -> (Color32, Color32) {
    (palette().wells[0], palette().well_edge)
}

/// Text on a highlighted (pastel) row.
pub const TEXT_ON_FILL: Color32 = Color32::from_rgb(0x1A, 0x1A, 0x1A);

/// Row highlights, same values as `LV_COLOR_*` in the C build.
pub const FILL_INVALID: Color32 = Color32::from_rgb(0xFF, 0x7C, 0x94);
pub const FILL_SPECIAL: Color32 = Color32::from_rgb(0xFF, 0xFF, 0xAA);
pub const FILL_SIGNED: Color32 = Color32::from_rgb(0xAE, 0xE4, 0xA2);
pub const FILL_CONNECTION: Color32 = Color32::from_rgb(0xFF, 0xA8, 0xF2);
pub const FILL_SYSTEM: Color32 = Color32::from_rgb(0x96, 0xC4, 0xFA);
pub const FILL_UNDELETE: Color32 = Color32::from_rgb(0xD4, 0xD4, 0xD4);

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

/// The type scale, in points before the View > Font scale. Every text size in
/// the window is one of these.
pub const CAPTION: f32 = 11.0;
pub const SMALL: f32 = 12.5;
pub const BODY: f32 = 13.0;
pub const TITLE: f32 = 16.0;
pub const DISPLAY: f32 = 18.0;

/// Text scale from View > Font, as f32 bits (1.0 by default).
static TEXT_SCALE: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0x3F80_0000);

/// A size in points at the chosen text scale.
pub fn px(size: f32) -> f32 {
    size * f32::from_bits(TEXT_SCALE.load(Ordering::Relaxed))
}

pub fn semibold(size: f32) -> FontId {
    FontId::new(px(size), FontFamily::Name(SEMIBOLD.into()))
}

/// Regular text at the chosen text scale.
pub fn body(size: f32) -> FontId {
    FontId::proportional(px(size))
}

/// Text sizes for a font size in points (View > Font); 0 keeps the default,
/// 13 px body text, which is about Windows' 9 pt at 100% scaling.
pub fn set_text_size(ctx: &egui::Context, points: u64) {
    let scale = if points == 0 { 1.0 } else { (points as f32 * 96.0 / 72.0 / 13.0).clamp(0.7, 2.0) };
    TEXT_SCALE.store(scale.to_bits(), Ordering::Relaxed);
    ctx.style_mut(|style| {
        style.text_styles = [
            (TextStyle::Small, FontId::proportional(CAPTION * scale)),
            (TextStyle::Body, FontId::proportional(BODY * scale)),
            (TextStyle::Button, FontId::proportional(BODY * scale)),
            (TextStyle::Heading, semibold(TITLE)),
            (TextStyle::Monospace, FontId::monospace(SMALL * scale)),
        ]
        .into();
    });
}

/// Fonts are loaded once; `set_theme` can run again when the theme changes.
pub fn apply(ctx: &egui::Context, accent: Color32, dark: bool, follow_system: bool, language: &str, face: &str, size: u64) {
    MOTION.store(super::shell::animations_enabled(), Ordering::Relaxed);
    install_fonts(ctx, language, face);
    set_text_size(ctx, size);
    set_theme(ctx, accent, dark, follow_system);
    ctx.style_mut(|style| {
        style.spacing.item_spacing = Vec2::new(8.0, 6.0);
        style.spacing.button_padding = Vec2::new(10.0, 4.0);
        style.spacing.interact_size.y = 26.0;
        style.spacing.menu_margin = egui::Margin::same(6);
        style.spacing.window_margin = egui::Margin::same(16);
        style.spacing.scroll.floating = true;
        style.spacing.scroll.bar_width = 8.0;
        // A thin handle stays visible at rest, so content past the edge has a cue.
        style.spacing.scroll.dormant_handle_opacity = 0.5;
        style.interaction.selectable_labels = false;
        style.interaction.tooltip_delay = 0.4;
        style.animation_time = motion(style.animation_time);
    });
}

/// Windows' "Animation effects" (Settings > Accessibility > Visual effects).
static MOTION: AtomicBool = AtomicBool::new(true);

/// An animation length, or zero when Windows has animations turned off.
pub fn motion(seconds: f32) -> f32 {
    if MOTION.load(Ordering::Relaxed) {
        seconds
    } else {
        0.0
    }
}

/// The accent where it is drawn as a line or text on the window's surfaces.
/// A light accent such as Windows' amber is darkened on light surfaces until it
/// reaches 4.5:1, so links, the tab underline, and selection stay visible.
pub fn accent_ink(accent: Color32) -> Color32 {
    if is_dark() {
        return accent;
    }
    let background = LIGHT.surface;
    (0..=20)
        .map(|step| lerp(accent, Color32::BLACK, step as f32 / 20.0))
        .find(|c| contrast(*c, background) >= 4.5)
        .unwrap_or(LIGHT.text)
}

fn lerp(a: Color32, b: Color32, t: f32) -> Color32 {
    let mix = |x: u8, y: u8| (x as f32 + (y as f32 - x as f32) * t).round() as u8;
    Color32::from_rgb(mix(a.r(), b.r()), mix(a.g(), b.g()), mix(a.b(), b.b()))
}

/// WCAG contrast ratio of two opaque colors.
pub fn contrast(a: Color32, b: Color32) -> f32 {
    let luminance = |c: Color32| {
        let channel = |v: u8| {
            let s = v as f32 / 255.0;
            if s <= 0.04045 {
                s / 12.92
            } else {
                ((s + 0.055) / 1.055).powf(2.4)
            }
        };
        0.2126 * channel(c.r()) + 0.7152 * channel(c.g()) + 0.0722 * channel(c.b())
    };
    let (x, y) = (luminance(a), luminance(b));
    (x.max(y) + 0.05) / (x.min(y) + 0.05)
}

/// `follow_system` leaves the title bar to Windows; otherwise it matches `dark`.
pub fn set_theme(ctx: &egui::Context, accent: Color32, dark: bool, follow_system: bool) {
    IS_DARK.store(dark, Ordering::Relaxed);
    let p = palette();
    let mut visuals = if dark { egui::Visuals::dark() } else { egui::Visuals::light() };
    visuals.panel_fill = p.chrome;
    visuals.window_fill = p.raised;
    visuals.extreme_bg_color = p.surface;
    visuals.faint_bg_color = p.faces[0];
    visuals.code_bg_color = p.surface;
    visuals.hyperlink_color = accent_ink(accent);
    // 0.32 keeps body text on a selected item at 4.5:1 or better.
    visuals.selection.bg_fill = accent.gamma_multiply(0.32);
    visuals.selection.stroke = Stroke::new(1.0_f32, p.text);
    visuals.window_stroke = Stroke::new(1.0_f32, p.border);
    visuals.window_corner_radius = CornerRadius::same(8);
    visuals.menu_corner_radius = CornerRadius::same(6);
    let shadow = Shadow {
        offset: [0, 4],
        blur: 16,
        spread: 0,
        color: Color32::from_black_alpha(if dark { 110 } else { 40 }),
    };
    visuals.window_shadow = shadow;
    visuals.popup_shadow = shadow;
    visuals.indent_has_left_vline = false;
    visuals.text_cursor.stroke = Stroke::new(1.5_f32, accent_ink(accent));

    let strong = if dark { Color32::WHITE } else { Color32::BLACK };
    let widgets = &mut visuals.widgets;
    widgets.noninteractive.bg_fill = p.chrome;
    widgets.noninteractive.weak_bg_fill = p.chrome;
    widgets.noninteractive.bg_stroke = Stroke::new(1.0_f32, p.border);
    widgets.noninteractive.fg_stroke = Stroke::new(1.0_f32, p.text);
    for (state, fill) in [
        (&mut widgets.inactive, p.faces[0]),
        (&mut widgets.hovered, p.faces[1]),
        (&mut widgets.active, p.faces[2]),
        (&mut widgets.open, p.faces[1]),
    ] {
        state.bg_fill = fill;
        state.weak_bg_fill = fill;
        state.corner_radius = CornerRadius::same(4);
        state.expansion = 0.0;
    }
    // bg_fill is the checkbox and radio well; weak_bg_fill stays the button face.
    widgets.inactive.bg_fill = p.wells[0];
    widgets.hovered.bg_fill = p.wells[1];
    widgets.inactive.bg_stroke = Stroke::new(1.0_f32, p.well_edge);
    widgets.inactive.fg_stroke = Stroke::new(1.0_f32, p.text);
    widgets.hovered.bg_stroke = Stroke::new(1.0_f32, p.well_edge);
    widgets.hovered.fg_stroke = Stroke::new(1.0_f32, strong);
    widgets.active.bg_stroke = Stroke::new(1.0_f32, accent);
    widgets.active.fg_stroke = Stroke::new(1.0_f32, strong);
    widgets.open.bg_stroke = Stroke::new(1.0_f32, p.border);
    widgets.open.fg_stroke = Stroke::new(1.0_f32, p.text);
    ctx.set_visuals(visuals);
    ctx.send_viewport_cmd(egui::ViewportCommand::SetTheme(if follow_system {
        egui::SystemTheme::SystemDefault
    } else if dark {
        egui::SystemTheme::Dark
    } else {
        egui::SystemTheme::Light
    }));
}

/// Windows' app theme (`AppsUseLightTheme`), for the "System" choice.
pub fn system_is_dark() -> bool {
    super::shell::apps_use_light_theme().map_or(true, |light| !light)
}

/// Segoe UI from the system font folder, with egui's bundled font as fallback.
/// `language` adds the system font that language needs, for scripts Segoe UI lacks.
pub fn install_fonts(ctx: &egui::Context, language: &str, face: &str) {
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
    // A font picked with View > Font comes first, ahead of Segoe UI.
    if let Some(bytes) = (!face.is_empty()).then(|| super::shell::font_file(face)).flatten().and_then(|p| std::fs::read(p).ok()) {
        fonts.font_data.insert("chosen".into(), Arc::new(FontData::from_owned(bytes)));
        regular.insert(0, "chosen".into());
        bold.insert(0, "chosen".into());
    }
    // After Segoe UI, before the bundled fallback.
    if let Some(bytes) = crate::i18n::extra_fonts(language).iter().find_map(|name| std::fs::read(dir.join(name)).ok()) {
        fonts.font_data.insert("script".into(), Arc::new(FontData::from_owned(bytes)));
        for family in [&mut regular, &mut bold] {
            let at = usize::from(!family.is_empty() && family[0].starts_with("segoe"));
            family.insert(at.min(family.len()), "script".into());
        }
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
