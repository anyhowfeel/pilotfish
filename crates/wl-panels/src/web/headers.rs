//! Aligned two-column header table: auto key column, wrapping/eliding values, click to copy.

use wl_kit::egui::{self, Align, Label, Layout, RichText, Sense, Stroke, TextStyle, Ui, vec2};
use wl_kit::theme::{Palette, spacing, tint};
use wl_kit::widgets::{text_width, toast};

use super::card::muted;

const MIN_KEY_W: f32 = 56.0;
/// Values longer than this are elided on one line (full text in the tooltip).
const LONG_VALUE: usize = 140;

/// Shared key column width: widest key, clamped to `[MIN_KEY_W, cap]`.
pub fn key_col_width(key_widths: impl IntoIterator<Item = f32>, cap: f32) -> f32 {
    let widest = key_widths.into_iter().fold(0.0_f32, f32::max);
    widest.ceil().clamp(MIN_KEY_W, cap.max(MIN_KEY_W))
}

pub fn headers_table(ui: &mut Ui, headers: &[(String, String)]) {
    if headers.is_empty() {
        muted(ui, "No headers");
        return;
    }
    let font = TextStyle::Body.resolve(ui.style());
    let widths: Vec<f32> = headers
        .iter()
        .map(|(k, _)| text_width(ui, k, font.clone()))
        .collect();
    let kw = key_col_width(widths, ui.available_width() * 0.4);
    ui.scope(|ui| {
        ui.spacing_mut().item_spacing.y = 0.0;
        for (i, (k, v)) in headers.iter().enumerate() {
            header_row(ui, i, k, v, kw);
        }
    });
}

fn header_row(ui: &mut Ui, i: usize, k: &str, v: &str, kw: f32) {
    if i > 0 {
        let (r, _) = ui.allocate_exact_size(vec2(ui.available_width(), 1.0), Sense::hover());
        ui.painter()
            .rect_filled(r, 0.0, tint(Palette::border(), 110));
    }
    let w = ui.available_width();
    let vw = (w - kw - spacing::MD).max(40.0);
    let long = v.chars().count() > LONG_VALUE;
    let out = ui.scope(|ui| {
        ui.add_space(spacing::XS);
        ui.horizontal_top(|ui| {
            ui.spacing_mut().item_spacing.x = spacing::MD;
            ui.allocate_ui_with_layout(vec2(kw, 18.0), Layout::top_down(Align::Min), |ui| {
                ui.set_width(kw);
                ui.add(Label::new(RichText::new(k).color(Palette::muted())).truncate());
            });
            ui.allocate_ui_with_layout(vec2(vw, 18.0), Layout::top_down(Align::Min), |ui| {
                ui.set_width(vw);
                let l = Label::new(RichText::new(v).color(Palette::text())).selectable(false);
                ui.add(if long { l.truncate() } else { l.wrap() });
            });
        });
        ui.add_space(spacing::XS);
    });
    let rect = out.response.rect;
    let resp = ui.interact(rect, ui.scope_id().with(("hdr", i, k)), Sense::click());
    if resp.hovered() {
        ui.painter().rect_stroke(
            rect,
            3.0,
            Stroke::new(1.0, Palette::border()),
            egui::StrokeKind::Inside,
        );
    }
    let resp = resp.on_hover_cursor(egui::CursorIcon::PointingHand);
    if resp.clicked() {
        ui.ctx().copy_text(v.to_owned());
        toast::push(ui.ctx(), format!("Copied {k}"));
    }
    resp.on_hover_text(if long {
        v.to_owned()
    } else {
        "Click to copy value".to_owned()
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_column_tracks_widest_key_within_bounds() {
        assert_eq!(key_col_width([40.0, 90.2, 75.0], 200.0), 91.0);
        assert_eq!(key_col_width([400.0], 150.0), 150.0);
        assert_eq!(key_col_width([10.0], 150.0), MIN_KEY_W);
        assert_eq!(key_col_width([], 150.0), MIN_KEY_W);
    }
}
