//! Headless egui runner shared by the layout tests of this crate.

use wl_kit::egui::{self, Context, Rect, pos2, vec2};
use wl_kit::theme::Mode;

/// Runs `f` for three frames (layout settles) on a `width` x `height` screen at `scale`.
pub fn run(width: f32, height: f32, scale: f32, mode: Mode, mut f: impl FnMut(&mut egui::Ui)) {
    let ctx = Context::default();
    wl_kit::theme::apply_mode(&ctx, mode);
    for _ in 0..3 {
        let input = egui::RawInput {
            screen_rect: Some(Rect::from_min_size(
                pos2(0.0, 0.0),
                vec2(width / scale, height / scale),
            )),
            ..Default::default()
        };
        ctx.set_pixels_per_point(scale);
        ctx.run_ui(input, |ui| f(ui)).drop_without_applying_deltas();
    }
}

static NO_EXTRAS: std::sync::LazyLock<(wl_model::ThreatIntel, crate::insights::InsightRules)> =
    std::sync::LazyLock::new(Default::default);

/// Insight context with no security data, no threat lists and default rules.
pub fn plain() -> crate::features::InsightContext<'static> {
    crate::features::InsightContext {
        security: None,
        intel: &NO_EXTRAS.0,
        rules: &NO_EXTRAS.1,
    }
}
