//! Toolbar of the Files tab (protocol, search, save buttons) and the size warning banner.

use wl_kit::egui::{self, Align, CornerRadius, Frame, Layout, Margin, RichText, Stroke, Ui, vec2};
use wl_kit::format;
use wl_kit::theme::{Palette, RADIUS, spacing, tint};
use wl_kit::widgets::{Severity, segmented_w};

use super::model::{PROTOCOLS, total_size};
use super::{ObjectsAction, ObjectsPanel};
use crate::overview::filter_box;

const BTN_H: f32 = 28.0;

pub fn warning(ui: &mut Ui, text: &str) {
    let c = Severity::Warning.color();
    Frame::new()
        .fill(tint(c, 32))
        .stroke(Stroke::new(1.0, c))
        .corner_radius(CornerRadius::same(RADIUS))
        .inner_margin(Margin::symmetric(spacing::MD as i8, spacing::SM as i8))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(RichText::new(text).color(Palette::text()));
        });
}

impl ObjectsPanel {
    pub(super) fn toolbar(&mut self, ui: &mut Ui, out: &mut Vec<ObjectsAction>) {
        let (count, size, has_set) = match self.set() {
            Some(s) => (s.objects.len(), total_size(&s.objects), true),
            None => (0, 0, false),
        };
        let selected = self.selected_object().map(|o| (o.id, o.packet));
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing = vec2(spacing::SM, spacing::SM);
            let opts: Vec<(usize, &str)> = PROTOCOLS
                .iter()
                .enumerate()
                .map(|(i, (_, l))| (i, *l))
                .collect();
            if segmented_w(ui, &mut self.proto, &opts, 340.0) {
                self.query.clear();
            }
            if filter_box(ui, &mut self.query, "Name, host, type\u{2026}", 220.0) {
                self.dirty = true;
            }
            if has_set {
                ui.label(
                    RichText::new(format!(
                        "{} of {count} \u{b7} {}",
                        self.order.len(),
                        format::bytes(size)
                    ))
                    .small()
                    .color(Palette::muted()),
                );
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                let btn = |ui: &mut Ui, on: bool, label: &str| {
                    ui.add_enabled(on, egui::Button::new(label).min_size(vec2(0.0, BTN_H)))
                        .clicked()
                };
                if btn(ui, count > 0, "Save all\u{2026}") {
                    out.push(ObjectsAction::SaveAll);
                }
                if btn(ui, selected.is_some(), "Save\u{2026}")
                    && let Some((id, _)) = selected
                {
                    out.push(ObjectsAction::Save(id));
                }
                if btn(
                    ui,
                    selected.is_some_and(|(_, p)| p.is_some()),
                    "Show in Packets",
                ) && let Some((_, Some(p))) = selected
                {
                    out.push(ObjectsAction::ShowInPackets(p));
                }
            });
        });
    }
}
