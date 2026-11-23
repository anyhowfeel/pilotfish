//! Page header (large title, muted subtitle, right-pinned actions) and the health summary strip.
use wl_kit::egui::{self, Align, Button, CornerRadius, Frame, Layout, Margin, RichText, Ui};
use wl_kit::format;
use wl_kit::theme::{Palette, RADIUS, spacing};
use wl_kit::widgets::{Severity, chip_dot, severity_dot};

use super::actions::InsightsAction;

const BTN_H: f32 = 30.0;

/// Below this width the actions sit under the title instead of right-pinned beside it.
const NARROW: f32 = 680.0;

pub fn header(ui: &mut Ui, actions: &mut Vec<InsightsAction>) {
    let narrow = ui.available_width() < NARROW;
    let titles = |ui: &mut Ui| {
        ui.label(
            RichText::new("Network health")
                .strong()
                .size(26.0)
                .color(Palette::text()),
        );
    };
    if narrow {
        titles(ui);
        ui.add_space(spacing::SM);
        ui.horizontal(|ui| buttons(ui, actions, false));
    } else {
        ui.horizontal(|ui| {
            titles(ui);
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                buttons(ui, actions, true);
            });
        });
    }
}

/// Re-analyse + Export report; `rtl` = the container lays out right-to-left.
fn buttons(ui: &mut Ui, actions: &mut Vec<InsightsAction>, rtl: bool) {
    ui.spacing_mut().item_spacing.x = spacing::SM;
    let mut items = [
        ("Re-analyse", InsightsAction::Refresh),
        ("Export report", InsightsAction::ExportReport),
    ];
    if rtl {
        items.reverse();
    }
    for (label, act) in items {
        if ui
            .add(Button::new(label).min_size(egui::vec2(0.0, BTN_H)))
            .clicked()
        {
            actions.push(act);
        }
    }
}

/// Counts shown in the summary strip.
pub struct Summary {
    pub label: &'static str,
    pub severity: Severity,
    pub critical: usize,
    pub warning: usize,
    pub info: usize,
    pub packets: u64,
}

pub fn summary_strip(ui: &mut Ui, s: &Summary) {
    Frame::new()
        .fill(Palette::surface())
        .stroke(egui::Stroke::new(1.0, Palette::border()))
        .corner_radius(CornerRadius::same(RADIUS))
        .inner_margin(Margin::symmetric(spacing::LG as i8, spacing::MD as i8))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            let narrow = ui.available_width() < NARROW;
            let body = |ui: &mut Ui| {
                ui.spacing_mut().item_spacing = egui::vec2(spacing::SM, spacing::SM);
                severity_dot(ui, s.severity, 12.0);
                ui.label(RichText::new(s.label).strong().size(16.0));
                for (sev, n) in [
                    (Severity::Critical, s.critical),
                    (Severity::Warning, s.warning),
                    (Severity::Info, s.info),
                ] {
                    let text = format!("{n} {}", sev.label().to_lowercase());
                    chip_dot(ui, &text, false, Some(sev.color()));
                }
            };
            let packets = RichText::new(format!("{} packets analysed", format::count(s.packets)))
                .small()
                .color(Palette::muted());
            if narrow {
                ui.horizontal_wrapped(|ui| {
                    body(ui);
                    ui.label(packets);
                });
            } else {
                ui.horizontal(|ui| {
                    body(ui);
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        ui.label(packets);
                    });
                });
            }
        });
}
