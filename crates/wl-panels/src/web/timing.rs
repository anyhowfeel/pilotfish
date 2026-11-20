//! Mini waterfall: request -> response latency against the slowest request in the capture.

use wl_kit::egui::{Align2, CornerRadius, FontId, RichText, Sense, Ui, vec2};
use wl_kit::format;
use wl_kit::theme::{Palette, mono, spacing, tint};
use wl_model::HttpExchange;

use super::card::{card, muted};
use super::cells::latency;

const BAR_H: f32 = 10.0;

/// Fraction (0..=1) of the track a latency fills; never invisible for a real value.
pub fn fraction(ms: f64, max_ms: f64) -> f32 {
    if max_ms <= 0.0 || ms <= 0.0 {
        return 0.0;
    }
    ((ms / max_ms) as f32).clamp(0.02, 1.0)
}

pub fn timing_card(ui: &mut Ui, ex: &HttpExchange, max_ms: f64) {
    card(
        ui,
        "",
        |_| {},
        |ui| {
            let Some(ms) = ex.time_ms else {
                muted(ui, "No response seen, so there is no latency to show.");
                return;
            };
            let value_w = 78.0;
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = spacing::MD;
                let lbl = "Latency";
                ui.label(RichText::new(lbl).color(Palette::muted()));
                let track_w = (ui.available_width() - value_w - spacing::MD).max(40.0);
                let (rect, resp) = ui.allocate_exact_size(vec2(track_w, 22.0), Sense::hover());
                let bar = wl_kit::egui::Rect::from_center_size(rect.center(), vec2(track_w, BAR_H));
                let r = CornerRadius::same((BAR_H / 2.0) as u8);
                ui.painter().rect_filled(bar, r, Palette::surface_hi());
                let mut fill = bar;
                fill.set_width(bar.width() * fraction(ms, max_ms));
                ui.painter()
                    .rect_filled(fill, r, tint(Palette::accent(), 230));
                resp.on_hover_text(format!(
                    "{} of the slowest request ({})",
                    latency(ms),
                    latency(max_ms)
                ));
                let (vr, _) = ui.allocate_exact_size(vec2(value_w, 22.0), Sense::hover());
                ui.painter().text(
                    vr.right_center(),
                    Align2::RIGHT_CENTER,
                    latency(ms),
                    FontId::monospace(13.0),
                    Palette::text(),
                );
            });
            let line = format!(
                "Sent at {} \u{b7} request {} \u{b7} response {}",
                format::time_rel(ex.start_rel),
                format::bytes(ex.req_bytes),
                format::bytes(ex.resp_bytes)
            );
            ui.label(mono(line).small().color(Palette::muted()));
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fraction_is_scaled_and_clamped() {
        assert_eq!(fraction(50.0, 100.0), 0.5);
        assert_eq!(fraction(500.0, 100.0), 1.0);
        assert_eq!(fraction(0.1, 1000.0), 0.02);
        assert_eq!(fraction(10.0, 0.0), 0.0);
    }
}
