//! Dismissible error / notice banner shown above the page.
use eframe::egui::{self, Margin};
use wl_kit::theme::{self, Palette, spacing};

use crate::app::App;

impl App {
    pub(crate) fn banner(&mut self, ui: &mut egui::Ui) {
        let msg = self
            .ctrl
            .error()
            .map(|e| (e.to_string(), true))
            .or_else(|| self.startup_error.clone().map(|s| (s, true)))
            .or_else(|| self.hub.error.clone().map(|s| (s, true)))
            .or_else(|| self.ctrl.notice().map(|n| (n.to_string(), false)))
            .or_else(|| self.hub.notice.clone().map(|n| (n, false)));
        let Some((text, is_err)) = msg else { return };
        let color = if is_err {
            Palette::danger()
        } else {
            Palette::ok()
        };
        let frame = egui::Frame::new()
            .fill(theme::tint(color, 40))
            .stroke(egui::Stroke::new(1.0, color))
            .corner_radius(theme::RADIUS)
            .inner_margin(Margin::symmetric(spacing::MD as i8, spacing::SM as i8));
        let mut close = ui.input(|i| i.key_pressed(egui::Key::Escape));
        frame.show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.add(
                    egui::Label::new(egui::RichText::new(&text).color(Palette::text())).truncate(),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    close |= wl_kit::widgets::close_button(ui).clicked();
                });
            });
        });
        ui.add_space(spacing::SM);
        if close {
            self.ctrl.dismiss_messages();
            self.startup_error = None;
            self.hub.notice = None;
            self.hub.error = None;
        }
    }
}
