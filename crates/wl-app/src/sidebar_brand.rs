//! Sidebar brand row: the wordmark, hidden when the sidebar is collapsed.

use wl_kit::egui::{self, Align2, FontId, Sense, pos2, vec2};
use wl_kit::theme::{Palette, spacing};

use crate::shell::ICON_W;

const NAV_GLYPH_W: f32 = 18.0;

pub fn brand(ui: &mut egui::Ui, labels: bool) {
    let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), 36.0), Sense::hover());
    if !labels {
        return;
    }
    ui.painter().with_clip_rect(rect).text(
        pos2(
            rect.left() + spacing::MD + (ICON_W - NAV_GLYPH_W) / 2.0,
            rect.center().y,
        ),
        Align2::LEFT_CENTER,
        "pilotfish",
        FontId::proportional(19.0),
        Palette::text(),
    );
}
