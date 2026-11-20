//! Sidebar brand row: logo badge and wordmark.

use wl_kit::egui::{self, Align2, FontId, Rect, Sense, pos2, vec2};
use wl_kit::theme::{Palette, RADIUS, spacing};

use crate::shell::ICON_W;

pub fn brand(ui: &mut egui::Ui, labels: bool) {
    let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), 36.0), Sense::hover());
    let p = ui.painter();
    let cx = if labels {
        rect.left() + ICON_W / 2.0
    } else {
        rect.center().x
    };
    let badge = Rect::from_center_size(pos2(cx, rect.center().y), vec2(ICON_W, ICON_W));
    p.rect_filled(badge, RADIUS, Palette::accent());
    p.text(
        badge.center(),
        Align2::CENTER_CENTER,
        "W",
        FontId::proportional(16.0),
        Palette::on_accent(),
    );
    if !labels {
        return;
    }
    let text = Rect::from_min_max(
        pos2(badge.right() + spacing::SM, rect.top()),
        rect.right_bottom(),
    );
    p.with_clip_rect(text).text(
        pos2(text.left(), text.center().y),
        Align2::LEFT_CENTER,
        "wirelens",
        FontId::proportional(19.0),
        Palette::text(),
    );
}
