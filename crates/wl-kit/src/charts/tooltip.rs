//! Hover tooltip of the multi-series chart: time header, then one aligned row per series
//! (colour dot, name, right-aligned monospace value).

use eframe::egui::{
    self, Align, Align2, Color32, FontId, Id, LayerId, PopupAnchor, Rect, RichText, Sense, Tooltip,
    Ui, pos2, vec2,
};

use crate::theme::{Palette, spacing};
use crate::widgets::paint_elided;

const ROW_H: f32 = 20.0;
const DOT: f32 = 8.0;
const NAME_MAX_W: f32 = 180.0;

/// One tooltip row.
pub struct TipRow<'a> {
    pub color: Color32,
    pub name: &'a str,
    pub value: String,
}

fn text_w(ui: &Ui, text: &str, font: &FontId) -> f32 {
    ui.painter()
        .layout_no_wrap(text.to_owned(), font.clone(), Palette::text())
        .size()
        .x
}

/// Shows the tooltip next to the pointer (always open while called).
pub fn show(ui: &Ui, parent: Id, header: &str, rows: &[TipRow<'_>]) {
    let layer: LayerId = ui.layer_id();
    Tooltip::always_open(ui.ctx().clone(), layer, parent, PopupAnchor::Pointer).show(|ui| {
        ui.spacing_mut().item_spacing.y = spacing::XS;
        ui.label(RichText::new(header).strong().color(Palette::text()));
        let name_font = egui::TextStyle::Body.resolve(ui.style());
        let val_font = egui::TextStyle::Monospace.resolve(ui.style());
        let name_w = rows
            .iter()
            .map(|r| text_w(ui, r.name, &name_font))
            .fold(0.0, f32::max)
            .min(NAME_MAX_W);
        let val_w = rows
            .iter()
            .map(|r| text_w(ui, &r.value, &val_font))
            .fold(0.0, f32::max);
        let w = DOT + spacing::SM + name_w + spacing::LG + val_w;
        for r in rows {
            let (rect, _) = ui.allocate_exact_size(vec2(w, ROW_H), Sense::hover());
            paint_row(ui, rect, r, (&name_font, &val_font), (name_w, val_w));
        }
    });
}

fn paint_row(ui: &Ui, rect: Rect, r: &TipRow<'_>, fonts: (&FontId, &FontId), w: (f32, f32)) {
    let p = ui.painter();
    let cy = rect.center().y;
    p.circle_filled(pos2(rect.left() + DOT / 2.0, cy), DOT / 2.0, r.color);
    let name_rect = Rect::from_min_size(
        pos2(rect.left() + DOT + spacing::SM, rect.top()),
        vec2(w.0, ROW_H),
    );
    paint_elided(
        p,
        name_rect,
        r.name,
        fonts.0.clone(),
        Palette::text(),
        Align::Min,
    );
    p.text(
        pos2(rect.right(), cy),
        Align2::RIGHT_CENTER,
        &r.value,
        fonts.1.clone(),
        Palette::text(),
    );
}
