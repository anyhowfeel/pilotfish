//! Card chrome shared by every block of the detail pane.

use wl_kit::egui::{self, Align, CornerRadius, Frame, Layout, Margin, RichText, Stroke, Ui};
use wl_kit::theme::{Palette, RADIUS, spacing};

/// Surface card filling the available width; `title` is an optional small caps heading with
/// `right` content aligned to its right edge.
pub fn card<R>(
    ui: &mut Ui,
    title: &str,
    right: impl FnOnce(&mut Ui),
    body: impl FnOnce(&mut Ui) -> R,
) -> R {
    Frame::new()
        .fill(Palette::surface())
        .stroke(Stroke::new(1.0, Palette::border()))
        .corner_radius(CornerRadius::same(RADIUS))
        .inner_margin(Margin::same(spacing::MD as i8))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.spacing_mut().item_spacing.y = spacing::SM;
            if !title.is_empty() {
                ui.horizontal(|ui| {
                    ui.set_min_height(24.0);
                    ui.label(
                        RichText::new(title.to_uppercase())
                            .small()
                            .strong()
                            .color(Palette::muted()),
                    );
                    ui.with_layout(Layout::right_to_left(Align::Center), right);
                });
            }
            body(ui)
        })
        .inner
}

/// Small muted label.
pub fn muted(ui: &mut Ui, text: &str) {
    ui.add(egui::Label::new(RichText::new(text).color(Palette::muted())).wrap());
}
