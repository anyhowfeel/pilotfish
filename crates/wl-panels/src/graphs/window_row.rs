//! Row under the chart: the selected time window and what can be done with it.

use wl_kit::charts::TimeSelection;
use wl_kit::egui::{self, Align, Layout, RichText, Ui, vec2};
use wl_kit::format;
use wl_kit::theme::Palette;

use super::panel::GraphsAction;

/// Fixed height (always reserved: the chart never jumps).
pub const WINDOW_ROW_H: f32 = 28.0;

pub fn window_row(
    ui: &mut Ui,
    selection: &mut Option<TimeSelection>,
    actions: &mut Vec<GraphsAction>,
) {
    ui.allocate_ui_with_layout(
        vec2(ui.available_width(), WINDOW_ROW_H),
        Layout::left_to_right(Align::Center),
        |ui| {
            let Some(sel) = *selection else {
                return;
            };
            let text = format!(
                "{} \u{2013} {}  \u{b7}  {}",
                format::clock(sel.from),
                format::clock(sel.to),
                format::duration(sel.duration())
            );
            ui.label(RichText::new(text).color(Palette::text()));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui.button("Clear").clicked() {
                    *selection = None;
                }
                let show = egui::Button::new(
                    RichText::new("Show packets")
                        .strong()
                        .color(Palette::on_accent()),
                )
                .fill(Palette::accent());
                if ui.add(show).clicked() {
                    actions.push(GraphsAction::ShowPackets(sel.filter_expr()));
                }
            });
        },
    );
}
