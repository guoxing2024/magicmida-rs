//! Dark visual theme — one place for every colour and text size.

use eframe::egui::{self, Color32, CornerRadius, FontId, Stroke, TextStyle};

/// Window background.
pub const BG: Color32 = Color32::from_rgb(0x14, 0x16, 0x1b);
/// Panel / card background.
pub const PANEL: Color32 = Color32::from_rgb(0x1c, 0x1f, 0x26);
/// Slightly raised surface (inputs, log rows).
pub const SURFACE: Color32 = Color32::from_rgb(0x23, 0x27, 0x30);
/// Hairline border.
pub const BORDER: Color32 = Color32::from_rgb(0x2e, 0x33, 0x3e);

/// Primary text.
pub const TEXT: Color32 = Color32::from_rgb(0xd8, 0xdd, 0xe6);
/// Muted text (labels, secondary values).
pub const MUTED: Color32 = Color32::from_rgb(0x7c, 0x86, 0x96);

/// Brand accent — a cold cyan, used for the active phase and progress.
pub const ACCENT: Color32 = Color32::from_rgb(0x3d, 0xc8, 0xe0);
/// Success.
pub const GOOD: Color32 = Color32::from_rgb(0x4a, 0xd1, 0x8c);
/// Warning.
pub const WARN: Color32 = Color32::from_rgb(0xe8, 0xb3, 0x3d);
/// Error.
pub const FATAL: Color32 = Color32::from_rgb(0xe8, 0x5d, 0x5d);
/// Debug-level log text (deliberately dim).
pub const DIM: Color32 = Color32::from_rgb(0x5a, 0x62, 0x70);

/// Monospace font for values and log text.
pub fn mono(size: f32) -> FontId {
    FontId::monospace(size)
}

/// Proportional font for headings.
pub fn heading(size: f32) -> FontId {
    FontId::proportional(size)
}

/// Apply the theme to the egui context.
pub fn install(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();

    style.visuals = egui::Visuals::dark();
    style.visuals.panel_fill = BG;
    style.visuals.window_fill = PANEL;
    style.visuals.extreme_bg_color = SURFACE;
    style.visuals.override_text_color = Some(TEXT);
    style.visuals.window_stroke = Stroke::new(1.0_f32, BORDER);

    let radius = CornerRadius::same(6);
    style.visuals.widgets.noninteractive.corner_radius = radius;
    style.visuals.widgets.inactive.corner_radius = radius;
    style.visuals.widgets.hovered.corner_radius = radius;
    style.visuals.widgets.active.corner_radius = radius;

    style.visuals.widgets.inactive.bg_fill = SURFACE;
    style.visuals.widgets.inactive.weak_bg_fill = SURFACE;
    style.visuals.widgets.inactive.bg_stroke = Stroke::new(1.0_f32, BORDER);
    style.visuals.widgets.inactive.fg_stroke = Stroke::new(1.0_f32, TEXT);

    style.visuals.widgets.hovered.bg_fill = Color32::from_rgb(0x2c, 0x32, 0x3d);
    style.visuals.widgets.hovered.weak_bg_fill = Color32::from_rgb(0x2c, 0x32, 0x3d);
    style.visuals.widgets.hovered.bg_stroke = Stroke::new(1.0_f32, ACCENT);
    style.visuals.widgets.hovered.fg_stroke = Stroke::new(1.0_f32, Color32::WHITE);

    style.visuals.widgets.active.bg_fill = ACCENT;
    style.visuals.widgets.active.weak_bg_fill = ACCENT;
    style.visuals.widgets.active.fg_stroke = Stroke::new(1.0_f32, BG);

    style.visuals.selection.bg_fill = Color32::from_rgb(0x25, 0x4c, 0x58);
    style.visuals.selection.stroke = Stroke::new(1.0_f32, ACCENT);

    style.spacing.item_spacing = egui::vec2(8.0, 6.0);
    style.spacing.button_padding = egui::vec2(12.0, 6.0);

    style.text_styles = [
        (TextStyle::Small, FontId::proportional(11.0)),
        (TextStyle::Body, FontId::proportional(13.5)),
        (TextStyle::Button, FontId::proportional(13.5)),
        (TextStyle::Heading, heading(19.0)),
        (TextStyle::Monospace, mono(12.5)),
    ]
    .into();

    ctx.set_style(style);
}

/// Colour for a log severity.
pub fn level_color(level: mida_run::Level) -> Color32 {
    use mida_run::Level;
    match level {
        Level::Good => GOOD,
        Level::Warn => WARN,
        Level::Fatal => FATAL,
        Level::Debug => DIM,
        Level::Info => TEXT,
    }
}

