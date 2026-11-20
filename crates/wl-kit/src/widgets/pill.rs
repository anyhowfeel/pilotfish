//! Signature protocol pills and semantic badges: single DRY implementation reused everywhere.

use eframe::egui::{
    Color32, CornerRadius, FontId, Painter, Rect, Response, Sense, Stroke, StrokeKind, Ui, pos2,
    vec2,
};

use crate::theme::{Palette, mode, protocol_color, tint};
use crate::widgets::pill_label::abbreviate_protocol;
use crate::widgets::pill_look::{
    Look, look, pill_border_alpha, pill_fg_for, pill_fill_alpha, solid_ink,
};
use crate::widgets::text;

/// Fixed height of every pill and badge for clean vertical rhythm across tables and cards.
pub const PILL_HEIGHT: f32 = 20.0;
/// Uniform protocol-pill width in tables (fits "WebSocket"; longer names elide with a tooltip).
pub const PROTOCOL_PILL_W: f32 = 92.0;
/// Protocol column width: the pill plus equal padding on both sides (never touches a separator).
pub const PROTOCOL_COL_W: f32 = PROTOCOL_PILL_W + 2.0 * crate::theme::spacing::MD;
const PILL_RADIUS: u8 = (PILL_HEIGHT / 2.0) as u8;
const PAD_X: f32 = 8.0;
const DOT_R: f32 = 2.5;
const DOT_D: f32 = DOT_R * 2.0;
const DOT_GAP: f32 = 5.0;
const FONT_SIZE: f32 = 11.5;

/// Configuration for `pill(...)`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PillStyle {
    /// Minimum width in points (use a shared width in table columns for crisp alignment).
    pub min_width: f32,
    /// Maximum width in points before eliding the text inside the pill.
    pub max_width: f32,
    /// Show a subtle leading status dot in the pill's accent hue.
    pub dot: bool,
}

impl PillStyle {
    /// Auto-sized badge without leading dot (for tags like `loopback`).
    pub const fn badge() -> Self {
        Self {
            min_width: 0.0,
            max_width: 140.0,
            dot: false,
        }
    }

    /// Fixed-rhythm table column pill with leading dot.
    pub const fn column(min_width: f32) -> Self {
        Self {
            min_width,
            max_width: 112.0,
            dot: true,
        }
    }

    /// Toggle the leading dot.
    pub const fn with_dot(mut self, dot: bool) -> Self {
        self.dot = dot;
        self
    }

    /// Override maximum width.
    pub const fn with_max_width(mut self, max_width: f32) -> Self {
        self.max_width = max_width;
        self
    }
}

/// Pure width math for a pill: pads text + optional dot, then clamps to `[min_width, max_width]`.
pub fn pill_width(text_w: f32, style: PillStyle) -> f32 {
    let dot_w = if style.dot { DOT_D + DOT_GAP } else { 0.0 };
    let natural = (text_w.max(0.0) + dot_w + 2.0 * PAD_X).ceil();
    let max_w = style.max_width.max(style.min_width).max(2.0 * PAD_X);
    natural.max(style.min_width).min(max_w)
}

/// Available inner text width inside a pill of total `width`.
pub fn pill_inner_text_width(width: f32, dot: bool) -> f32 {
    let dot_w = if dot { DOT_D + DOT_GAP } else { 0.0 };
    (width - 2.0 * PAD_X - dot_w).max(1.0)
}

/// Render a pill with optional leading dot, AA-contrast text centered on both axes, and elision + tooltip.
pub fn pill(ui: &mut Ui, label: &str, color: Color32, style: PillStyle) -> Response {
    pill_with_tooltip(ui, label, label, color, style)
}

/// Signature protocol pill: uses `protocol_color(protocol)`, leading dot, uniform column `min_width`,
/// smart abbreviation/elision, and hover tooltip showing the full protocol name.
pub fn protocol_pill(ui: &mut Ui, protocol: &str, min_width: f32) -> Response {
    let display = abbreviate_protocol(protocol);
    let color = protocol_color(protocol);
    let style = PillStyle::column(min_width);
    pill_with_tooltip(ui, &display, protocol.trim(), color, style)
}

/// Protocol pill centered on the horizontal middle of its table cell (`ui.max_rect()`), whatever
/// the layout spacing; vertically it follows the cell's own centering.
pub fn protocol_pill_centered(ui: &mut Ui, protocol: &str, min_width: f32) -> Response {
    let display = abbreviate_protocol(protocol);
    let color = protocol_color(protocol);
    let center_x = ui.max_rect().center().x;
    pill_in(
        ui,
        &display,
        protocol.trim(),
        color,
        PillStyle::column(min_width),
        Some(center_x),
    )
}

/// Small rounded colored tag (backwards-compatible wrapper around `pill`).
pub fn badge(ui: &mut Ui, label: &str, color: Color32) -> Response {
    pill(ui, label, color, PillStyle::badge())
}

fn pill_with_tooltip(
    ui: &mut Ui,
    display: &str,
    full: &str,
    color: Color32,
    style: PillStyle,
) -> Response {
    pill_in(ui, display, full, color, style, None)
}

/// Shared drawing path; `center_x` re-centers the pill horizontally on that x (table cells).
fn pill_in(
    ui: &mut Ui,
    display: &str,
    full: &str,
    color: Color32,
    style: PillStyle,
    center_x: Option<f32>,
) -> Response {
    let raw_tw = text::text_width(ui, display, FontId::proportional(FONT_SIZE));
    let avail = ui.available_width().max(2.0 * PAD_X);
    let target_w = pill_width(raw_tw, style).min(avail);
    let (mut rect, mut resp) = ui.allocate_exact_size(vec2(target_w, PILL_HEIGHT), Sense::hover());
    if let Some(cx) = center_x {
        rect = rect.translate(vec2(cx - rect.center().x, 0.0));
        resp = resp.with_new_rect(rect);
    }

    let elided = paint_pill(ui.painter(), rect, display, color, style);
    if (elided || display != full) && !full.is_empty() {
        resp.on_hover_text(full)
    } else {
        resp
    }
}

/// Paints a pill into `rect` (tinted fill, border, optional dot, centred AA text).
/// Returns true when the text had to be elided.
pub fn paint_pill(
    p: &Painter,
    rect: Rect,
    display: &str,
    color: Color32,
    style: PillStyle,
) -> bool {
    let font = FontId::proportional(FONT_SIZE);
    let m = mode();
    let look = look();
    let r = CornerRadius::same(PILL_RADIUS);
    let fg = match look {
        Look::Tinted => pill_fg_for(color, m),
        Look::Solid => solid_ink(color),
        Look::Dot => Palette::text(),
    };
    match look {
        Look::Tinted => {
            p.rect_filled(rect, r, tint(color, pill_fill_alpha(m)));
            p.rect_stroke(
                rect,
                r,
                Stroke::new(1.0, tint(color, pill_border_alpha(m))),
                StrokeKind::Inside,
            );
        }
        Look::Solid => {
            p.rect_filled(rect, r, color);
        }
        // Just the coloured dot and the text: no chrome at all.
        Look::Dot => {}
    }
    let show_dot = style.dot && rect.width() >= 2.0 * PAD_X + DOT_D + DOT_GAP + 8.0;
    let inner_w = pill_inner_text_width(rect.width(), show_dot);
    let galley = text::elided_galley(p, display, font, fg, inner_w);
    let elided = galley.rows.len() > 1 || galley.elided;
    let gsize = galley.size();
    let dot_w = if show_dot { DOT_D + DOT_GAP } else { 0.0 };
    let start_x = rect.center().x - (dot_w + gsize.x) / 2.0;
    let clip = p.with_clip_rect(rect.shrink2(vec2(PAD_X * 0.5, 0.0)));
    if show_dot {
        clip.circle_filled(pos2(start_x + DOT_R, rect.center().y), DOT_R, color);
    }
    let text_pos = pos2(start_x + dot_w, (rect.center().y - gsize.y / 2.0).round());
    clip.galley(text_pos, galley, fg);
    elided
}

/// Paints a pill whose left edge is `left` and vertical centre `cy` (no layout allocation); returns its rect.
pub fn pill_at(ui: &Ui, left: f32, cy: f32, label: &str, color: Color32, style: PillStyle) -> Rect {
    let tw = text::text_width(ui, label, FontId::proportional(FONT_SIZE));
    let w = pill_width(tw, style);
    let rect = Rect::from_min_size(pos2(left, cy - PILL_HEIGHT / 2.0), vec2(w, PILL_HEIGHT));
    paint_pill(ui.painter(), rect, label, color, style);
    rect
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_math_respects_min_max_and_dot() {
        let s_badge = PillStyle::badge();
        assert_eq!(pill_width(24.0, s_badge), 40.0);
        let s_col = PillStyle::column(68.0);
        assert_eq!(pill_width(20.0, s_col), 68.0);
        assert_eq!(pill_width(60.0, s_col), 86.0);
        assert_eq!(pill_width(200.0, s_col), s_col.max_width);
        assert!(pill_inner_text_width(68.0, true) < pill_inner_text_width(68.0, false));
        assert_eq!(PILL_HEIGHT, 20.0);
    }
}
