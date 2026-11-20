//! Compact rectangular toggle chip with a clear on/off state and an optional trailing count.
//! Painted at an exact pre-computed size so a row of chips shares one baseline and height.

use eframe::egui::{
    Color32, CornerRadius, CursorIcon, FontId, Painter, Pos2, Response, Sense, Stroke, StrokeKind,
    Ui, pos2, vec2,
};

use crate::theme::{Palette, spacing};
use crate::widgets::text;

pub const TOGGLE_CHIP_H: f32 = 24.0;
const PAD_X: f32 = spacing::SM;
const GAP: f32 = spacing::XS + 2.0;
const RADIUS: u8 = 4;

fn label_font() -> FontId {
    FontId::proportional(12.5)
}

fn count_font() -> FontId {
    FontId::monospace(11.0)
}

/// Width `toggle_chip` will occupy (for fitting a row without wrapping).
pub fn toggle_chip_width(ui: &Ui, label: &str, count: Option<&str>) -> f32 {
    let mut w = text::text_width(ui, label, label_font()) + 2.0 * PAD_X;
    if let Some(c) = count {
        w += GAP + text::text_width(ui, c, count_font());
    }
    w.ceil()
}

fn paint_text(p: &Painter, at: Pos2, cy: f32, s: &str, font: FontId, color: Color32) -> f32 {
    let g = p.layout_no_wrap(s.to_owned(), font, color);
    let w = g.size().x;
    p.galley(pos2(at.x, (cy - g.size().y / 2.0).round()), g, color);
    w
}

/// Toggle chip: `on` is drawn with an accent fill, accent border and full-contrast text.
/// The caller flips its own state when the response is `clicked()`.
pub fn toggle_chip(ui: &mut Ui, on: bool, label: &str, count: Option<&str>) -> Response {
    toggle_chip_h(ui, on, label, count, TOGGLE_CHIP_H)
}

/// `toggle_chip` with an explicit height (to line up with 28 px inputs and buttons).
pub fn toggle_chip_h(ui: &mut Ui, on: bool, label: &str, count: Option<&str>, h: f32) -> Response {
    let w = toggle_chip_width(ui, label, count);
    let (rect, resp) = ui.allocate_exact_size(vec2(w, h), Sense::click());
    let (fill, border, fg, sub) = if on {
        (
            Palette::selection_bg(),
            Palette::accent(),
            Palette::text(),
            Palette::text(),
        )
    } else if resp.hovered() {
        (
            Palette::surface_hi(),
            Palette::border(),
            Palette::text(),
            Palette::muted(),
        )
    } else {
        (
            Palette::surface(),
            Palette::border(),
            Palette::muted(),
            Palette::muted(),
        )
    };
    let r = CornerRadius::same(RADIUS);
    let p = ui.painter();
    p.rect_filled(rect, r, fill);
    p.rect_stroke(rect, r, Stroke::new(1.0, border), StrokeKind::Inside);
    let cy = rect.center().y;
    let mut x = rect.left() + PAD_X;
    x += paint_text(p, pos2(x, cy), cy, label, label_font(), fg);
    if let Some(c) = count {
        paint_text(p, pos2(x + GAP, cy), cy, c, count_font(), sub);
    }
    resp.on_hover_cursor(CursorIcon::PointingHand)
}

const CHEVRON_W: f32 = 18.0;

pub fn menu_chip_width(ui: &Ui, label: &str) -> f32 {
    (text::text_width(ui, label, label_font()) + 2.0 * PAD_X + CHEVRON_W).ceil()
}

/// Chip-styled drop-down trigger ("Quick filters v"). Open it with
/// `egui::Popup::menu(&response)`; `on` paints the accent state (something inside is active).
pub fn menu_chip(ui: &mut Ui, label: &str, on: bool) -> Response {
    let w = menu_chip_width(ui, label);
    let (rect, resp) = ui.allocate_exact_size(vec2(w, TOGGLE_CHIP_H), Sense::click());
    let (fill, border, fg) = if on {
        (Palette::selection_bg(), Palette::accent(), Palette::text())
    } else if resp.hovered() {
        (Palette::surface_hi(), Palette::border(), Palette::text())
    } else {
        (Palette::surface(), Palette::border(), Palette::muted())
    };
    let r = CornerRadius::same(RADIUS);
    let p = ui.painter();
    p.rect_filled(rect, r, fill);
    p.rect_stroke(rect, r, Stroke::new(1.0, border), StrokeKind::Inside);
    let cy = rect.center().y;
    paint_text(
        p,
        pos2(rect.left() + PAD_X, cy),
        cy,
        label,
        label_font(),
        fg,
    );
    let c = pos2(rect.right() - PAD_X - 3.5, cy);
    let s = Stroke::new(1.5, fg);
    p.line_segment([pos2(c.x - 3.5, c.y - 1.5), pos2(c.x, c.y + 2.0)], s);
    p.line_segment([pos2(c.x, c.y + 2.0), pos2(c.x + 3.5, c.y - 1.5)], s);
    resp.on_hover_cursor(CursorIcon::PointingHand)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn width_grows_with_count_and_chip_has_fixed_height() {
        let ctx = eframe::egui::Context::default();
        for _ in 0..2 {
            let input = eframe::egui::RawInput {
                screen_rect: Some(eframe::egui::Rect::from_min_size(
                    eframe::egui::Pos2::ZERO,
                    eframe::egui::vec2(400.0, 300.0),
                )),
                ..Default::default()
            };
            ctx.run_ui(input, |ui| {
                let a = toggle_chip_width(ui, "TCP", None);
                let b = toggle_chip_width(ui, "TCP", Some("214"));
                assert!(b > a);
                let r = toggle_chip(ui, true, "TCP", Some("214"));
                assert_eq!(r.rect.height(), TOGGLE_CHIP_H);
                assert_eq!(r.rect.width(), b);
            })
            .drop_without_applying_deltas();
        }
    }
}
