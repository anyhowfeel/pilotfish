//! Form rows built on `settings_row`: segmented choice, text, number, read-only value, shortcut.
use eframe::egui::{self, Align, Layout, RichText, Ui};

use super::rows::{CONTROL_W, settings_row};
use super::segmented::segmented;
use crate::theme::{Palette, mono};

/// Row with a segmented control. Returns true when the selection changed.
pub fn choice_row<T: PartialEq + Copy>(
    ui: &mut Ui,
    first: bool,
    label: &str,
    desc: &str,
    value: &mut T,
    options: &[(T, &str)],
) -> bool {
    settings_row(ui, first, label, desc, |ui| segmented(ui, value, options))
}

/// Row with a single-line text field (monospace).
pub fn text_row(
    ui: &mut Ui,
    first: bool,
    label: &str,
    desc: &str,
    value: &mut String,
    hint: &str,
) -> bool {
    settings_row(ui, first, label, desc, |ui| {
        let w = ui.available_width().min(CONTROL_W);
        ui.add(
            crate::widgets::text_field(value)
                .hint_text(hint)
                .font(egui::TextStyle::Monospace)
                .desired_width(w),
        )
        .changed()
    })
}

/// Row with an integer drag-value (`0` may mean "off" - say so in `desc`).
pub fn number_row(
    ui: &mut Ui,
    first: bool,
    label: &str,
    desc: &str,
    value: &mut u32,
    range: std::ops::RangeInclusive<u32>,
    suffix: &str,
) -> bool {
    settings_row(ui, first, label, desc, |ui| {
        ui.add(
            egui::DragValue::new(value)
                .range(range)
                .suffix(suffix)
                .speed(1.0),
        )
        .changed()
    })
}

/// Read-only value row (monospace, right aligned, elided).
pub fn info_row(ui: &mut Ui, first: bool, label: &str, value: &str) {
    settings_row(ui, first, label, "", |ui| {
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.add(egui::Label::new(mono(value).color(Palette::muted())).truncate())
                .on_hover_text(value);
        });
    });
}

/// Read-only keybinding row: description left, key combo right.
pub fn shortcut_row(ui: &mut Ui, first: bool, what: &str, keys: &str) {
    settings_row(ui, first, what, "", |ui| {
        ui.label(RichText::new(keys).monospace().color(Palette::text()));
    });
}
