//! Compact label/value rows of the properties dialog (fixed height, text centred).

use wl_kit::egui::{self, Align, Rect, Sense, Ui, pos2, vec2};
use wl_kit::theme::{Palette, spacing};
use wl_kit::widgets::paint_elided;

pub const ROW_H: f32 = 32.0;
pub const LABEL_W: f32 = 132.0;

/// A monospace value on its own line spanning the whole card, selectable by the user.
pub fn kv_full_row(ui: &mut Ui, value: &str) {
    let (row, resp) = ui.allocate_exact_size(vec2(ui.available_width(), ROW_H), Sense::click());
    let font = egui::TextStyle::Monospace.resolve(ui.style());
    paint_elided(ui.painter(), row, value, font, Palette::text(), Align::Min);
    if resp.on_hover_text("Click to copy").clicked() {
        ui.ctx().copy_text(value.to_owned());
    }
}

/// Draws `label` (muted) and `value` (monospace when `mono`), a hairline above unless `first`.
/// `reserve` keeps that much width free at the right end of the row, whose rect is returned
/// (for a button).
pub fn kv_row(
    ui: &mut Ui,
    first: bool,
    label: &str,
    value: &str,
    mono: bool,
    reserve: f32,
) -> Rect {
    if !first {
        let (line, _) = ui.allocate_exact_size(vec2(ui.available_width(), 1.0), Sense::hover());
        ui.painter().rect_filled(line, 0.0, Palette::border());
    }
    let (row, resp) = ui.allocate_exact_size(vec2(ui.available_width(), ROW_H), Sense::hover());
    let p = ui.painter();
    let label_rect = Rect::from_min_size(row.min, vec2(LABEL_W, ROW_H));
    paint_elided(
        p,
        label_rect,
        label,
        egui::TextStyle::Body.resolve(ui.style()),
        Palette::muted(),
        Align::Min,
    );
    let x0 = row.left() + LABEL_W + spacing::MD;
    let value_rect = Rect::from_min_max(
        pos2(x0, row.top()),
        pos2(row.right() - reserve, row.bottom()),
    );
    let style = if mono {
        egui::TextStyle::Monospace
    } else {
        egui::TextStyle::Body
    };
    let cut = paint_elided(
        p,
        value_rect,
        value,
        style.resolve(ui.style()),
        Palette::text(),
        Align::Min,
    );
    if cut {
        resp.on_hover_text(value);
    }
    Rect::from_min_max(pos2(row.right() - reserve, row.top()), row.right_bottom())
}
