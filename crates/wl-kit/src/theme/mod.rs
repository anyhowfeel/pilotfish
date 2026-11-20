//! Theme: palette, spacing tokens, egui style installation.

pub mod contrast;
pub mod cvd;
mod palette;
mod palette_defs;
mod protocol;
#[cfg(test)]
mod tests;

use std::sync::atomic::{AtomicU8, Ordering};

use eframe::egui::{self, Color32, CornerRadius, FontId, Stroke, TextStyle, Visuals};

pub use palette::{Colors, Palette, Theme};
pub use protocol::{protocol_color, protocol_color_for};

/// Row height of tables and ranked lists.
/// Row height of tables and ranked lists for the "Comfortable" density.
pub const ROW_H: f32 = 28.0;
/// Row height of the "Compact" density.
pub const ROW_H_COMPACT: f32 = 22.0;

static COMPACT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Switches table/list density (Settings > Appearance).
pub fn set_compact(on: bool) {
    COMPACT.store(on, Ordering::Relaxed);
}

/// Current row height of tables and ranked lists.
pub fn row_h() -> f32 {
    if COMPACT.load(Ordering::Relaxed) {
        ROW_H_COMPACT
    } else {
        ROW_H
    }
}
/// Corner radius of cards and controls.
pub const RADIUS: u8 = 8;

pub mod spacing {
    pub const XS: f32 = 4.0;
    pub const SM: f32 = 8.0;
    pub const MD: f32 = 12.0;
    pub const LG: f32 = 16.0;
    pub const XL: f32 = 24.0;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Mode {
    #[default]
    Dark,
    Light,
}

/// Alias for `Mode` (dark/light theme selection).
pub type ThemeMode = Mode;

static MODE: AtomicU8 = AtomicU8::new(0);
static THEME: AtomicU8 = AtomicU8::new(0);

pub fn mode() -> Mode {
    if MODE.load(Ordering::Relaxed) == 1 {
        Mode::Light
    } else {
        Mode::Dark
    }
}

/// Switch mode; takes effect on the next `apply(ctx)`.
pub fn set_mode(m: Mode) {
    MODE.store(u8::from(m == Mode::Light), Ordering::Relaxed);
}

/// Switch mode and apply visuals immediately.
pub fn apply_mode(ctx: &egui::Context, m: Mode) {
    set_mode(m);
    apply(ctx);
}

pub fn theme() -> Theme {
    let idx = THEME.load(Ordering::Relaxed) as usize;
    Theme::ALL.get(idx).copied().unwrap_or_default()
}

/// Switch color theme; takes effect on the next `apply(ctx)`.
pub fn set_theme(t: Theme) {
    let code = Theme::ALL.iter().position(|&x| x == t).unwrap_or(0) as u8;
    THEME.store(code, Ordering::Relaxed);
}

/// Switch color theme and apply visuals immediately.
pub fn apply_theme(ctx: &egui::Context, t: Theme) {
    set_theme(t);
    apply(ctx);
}

/// Monospace text for numbers (digits align in columns).
pub fn mono(text: impl Into<String>) -> egui::RichText {
    egui::RichText::new(text).monospace()
}

fn visuals(c: &Colors, dark: bool) -> Visuals {
    let mut v = if dark {
        Visuals::dark()
    } else {
        Visuals::light()
    };
    let r = CornerRadius::same(RADIUS);
    v.panel_fill = c.bg;
    v.window_fill = c.surface;
    v.extreme_bg_color = if dark { c.panel } else { c.surface };
    v.faint_bg_color = c.row_alt;
    v.window_stroke = Stroke::new(1.0, c.border);
    v.window_corner_radius = CornerRadius::same(RADIUS + 2);
    v.menu_corner_radius = r;
    v.override_text_color = Some(c.text);
    v.hyperlink_color = c.accent;
    v.warn_fg_color = c.warn;
    v.error_fg_color = c.danger;
    v.selection.bg_fill = c.selection_bg;
    // Selected table rows and selectable tabs use `selection.stroke.color` for text.
    v.selection.stroke = Stroke::new(1.0, c.text);
    v.text_cursor.stroke = Stroke::new(1.5, c.accent);
    let w = &mut v.widgets;
    for (wv, fill) in [
        (&mut w.noninteractive, c.surface),
        (&mut w.inactive, c.surface),
        (&mut w.hovered, c.surface_hi),
        (&mut w.active, c.surface_hi),
        (&mut w.open, c.surface_hi),
    ] {
        wv.bg_fill = fill;
        wv.weak_bg_fill = fill;
        wv.corner_radius = r;
        wv.bg_stroke = Stroke::new(1.0, c.border);
        wv.fg_stroke = Stroke::new(1.0, c.text);
    }
    w.noninteractive.bg_stroke = Stroke::new(1.0, c.border);
    w.noninteractive.fg_stroke = Stroke::new(1.0, c.muted);
    w.hovered.bg_stroke = Stroke::new(1.0, contrast::lerp_color(c.border, c.muted, 0.35));
    w.active.bg_stroke = Stroke::new(1.0, c.accent);
    v.striped = true;
    v
}

fn style(s: &mut egui::Style) {
    s.spacing.item_spacing = egui::vec2(spacing::SM, spacing::SM);
    s.spacing.button_padding = egui::vec2(spacing::MD, spacing::XS + 1.0);
    s.spacing.interact_size.y = 28.0;
    s.spacing.window_margin = egui::Margin::same(spacing::LG as i8);
    // Solid (non-floating) scroll bars reserve their own gutter, so they never overlap content.
    s.spacing.scroll = egui::style::ScrollStyle::solid();
    s.spacing.scroll.bar_width = 10.0;
    s.spacing.scroll.handle_min_length = 32.0;
    s.text_styles
        .insert(TextStyle::Small, FontId::proportional(11.5));
    s.text_styles
        .insert(TextStyle::Body, FontId::proportional(13.5));
    s.text_styles
        .insert(TextStyle::Button, FontId::proportional(13.5));
    s.text_styles
        .insert(TextStyle::Monospace, FontId::monospace(12.5));
    s.text_styles
        .insert(TextStyle::Heading, FontId::proportional(20.0));
}

/// Install fonts/style/visuals for the current `(Theme, Mode)`. Cheap to call every frame.
pub fn apply(ctx: &egui::Context) {
    let key = (theme(), mode());
    let id = egui::Id::NULL.with("wl_kit_theme_state");
    if ctx.data(|d| d.get_temp::<(Theme, Mode)>(id)) == Some(key) {
        return;
    }
    let egui_theme = match key.1 {
        Mode::Dark => egui::Theme::Dark,
        Mode::Light => egui::Theme::Light,
    };
    ctx.set_visuals_of(egui::Theme::Dark, visuals(key.0.colors(Mode::Dark), true));
    ctx.set_visuals_of(
        egui::Theme::Light,
        visuals(key.0.colors(Mode::Light), false),
    );
    ctx.set_theme(egui_theme);
    ctx.global_style_mut(style);
    ctx.data_mut(|d| d.insert_temp(id, key));
}

/// Translucent version of a color (for fills behind text).
pub fn tint(c: Color32, alpha: u8) -> Color32 {
    Color32::from_rgba_unmultiplied(c.r(), c.g(), c.b(), alpha)
}

/// Ink target used to tint pill foreground text toward the active theme's text polarity.
pub fn pill_ink_target(m: Mode) -> Color32 {
    Palette::colors_for(m).text
}
