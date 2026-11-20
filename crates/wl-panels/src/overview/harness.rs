//! Headless egui frame runner shared by the layout tests.

use wl_kit::egui::{self, Context, Rect, pos2, vec2};
use wl_kit::theme::Mode;

pub(super) fn run(width: f32, height: f32, scale: f32, mode: Mode, f: impl FnMut(&mut egui::Ui)) {
    run_extent(width, height, scale, mode, f);
}

/// Like `run`, returning the rightmost painted x (points) of the last frame.
pub(super) fn run_extent(
    width: f32,
    height: f32,
    scale: f32,
    mode: Mode,
    mut f: impl FnMut(&mut egui::Ui),
) -> f32 {
    let mut right = 0.0_f32;
    let ctx = Context::default();
    wl_kit::theme::apply_mode(&ctx, mode);
    for _ in 0..3 {
        let input = egui::RawInput {
            screen_rect: Some(Rect::from_min_size(
                pos2(0.0, 0.0),
                vec2(width / scale, height / scale),
            )),
            viewports: std::iter::once((
                egui::ViewportId::ROOT,
                egui::ViewportInfo {
                    native_pixels_per_point: Some(scale),
                    ..Default::default()
                },
            ))
            .collect(),
            ..Default::default()
        };
        ctx.set_pixels_per_point(scale);
        let out = ctx.run_ui(input, |ui| f(ui));
        right = out
            .shapes
            .iter()
            .map(|s| s.shape.visual_bounding_rect().right())
            .fold(0.0, f32::max);
        out.drop_without_applying_deltas();
    }
    right
}
