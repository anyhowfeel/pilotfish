//! Neutral chip: small rounded surface with muted (optionally monospace) text and optional dot.
//!
//! Painted with an exact pre-computed size (like the pills) instead of a `Frame`: egui does not
//! re-centre a `Frame` inside a centred row, which left chips lower than their neighbours.
use eframe::egui::{Color32, CornerRadius, CursorIcon, FontId, Response, Sense, Ui, pos2, vec2};

use crate::theme::{Palette, spacing};
use crate::widgets::text;

/// Fixed chip height: every chip in a row lines up regardless of its content.
pub const CHIP_H: f32 = 22.0;
const PAD_X: f32 = spacing::SM;
const DOT_D: f32 = 8.0;
const DOT_GAP: f32 = spacing::XS + 2.0;

/// Compact chip. `mono` renders digits/filters in monospace. Hover shows `text` in full.
pub fn chip(ui: &mut Ui, text: &str, mono: bool) -> Response {
    chip_dot(ui, text, mono, None)
}

/// Chip with an optional leading status dot (e.g. a severity colour).
pub fn chip_dot(ui: &mut Ui, label: &str, mono: bool, dot: Option<Color32>) -> Response {
    paint(ui, label, mono, dot, Sense::hover()).on_hover_text(label)
}

/// Monospace chip that copies its text when clicked (caller handles `.clicked()`): pointing-hand
/// cursor and a "Click to copy" tooltip make the affordance explicit.
pub fn chip_copy(ui: &mut Ui, label: &str) -> Response {
    paint(ui, label, true, None, Sense::click())
        .on_hover_text(format!("Click to copy\n{label}"))
        .on_hover_cursor(CursorIcon::Copy)
}

fn paint(ui: &mut Ui, label: &str, mono: bool, dot: Option<Color32>, sense: Sense) -> Response {
    let font = if mono {
        FontId::monospace(11.5)
    } else {
        FontId::proportional(12.0)
    };
    let color = if dot.is_some() {
        Palette::text()
    } else {
        Palette::muted()
    };
    let dot_w = if dot.is_some() { DOT_D + DOT_GAP } else { 0.0 };
    let natural = text::text_width(ui, label, font.clone()) + dot_w + 2.0 * PAD_X;
    let width = natural
        .ceil()
        .min(ui.available_width().max(2.0 * PAD_X + dot_w + 8.0));
    let (rect, resp) = ui.allocate_exact_size(vec2(width, CHIP_H), sense);

    let p = ui.painter();
    p.rect_filled(
        rect,
        CornerRadius::same((CHIP_H / 2.0) as u8),
        Palette::surface_hi(),
    );
    let mut x = rect.left() + PAD_X;
    if let Some(c) = dot {
        p.circle_filled(pos2(x + DOT_D / 2.0, rect.center().y), DOT_D / 2.0, c);
        x += DOT_D + DOT_GAP;
    }
    let inner_w = (rect.right() - PAD_X - x).max(1.0);
    let galley = text::elided_galley(p, label, font, color, inner_w);
    let y = (rect.center().y - galley.size().y / 2.0).round();
    p.galley(pos2(x, y), galley, color);
    resp
}
