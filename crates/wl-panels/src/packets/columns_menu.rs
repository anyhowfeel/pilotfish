//! Column chooser (show/hide/reorder/add/remove/reset) and time display format selector.
//! One body shared by the toolbar "Columns" menu and the header right-click menu.

use eframe::egui::{Align, Key, Layout, RichText, ScrollArea, Stroke, Ui, vec2};
use wl_kit::widgets::{MINI_BUTTON, MiniGlyph, mini_button, text_field};

use crate::packets::column_set::ColumnSet;
use crate::packets::columns::ColKey;
use crate::packets::kit::{Palette, spacing};
use crate::packets::time_format::TimeFormat;

pub const MENU_W: f32 = 290.0;

/// Edits `set` / `time` in place. `new_field` is the text box for "Add field".
pub fn show(
    ui: &mut Ui,
    set: &mut ColumnSet,
    time: &mut TimeFormat,
    new_field: &mut String,
    time_ref: &mut Option<(u64, f64)>,
) {
    ui.set_min_width(MENU_W);
    ui.set_max_width(MENU_W);
    ui.spacing_mut().interact_size.y = 24.0;
    // Short windows: scroll instead of running off screen (a ScrollArea always clips to
    // the popup's available height, so it is only used when the menu really cannot fit).
    let need = (set.specs().len() as f32 + 9.0) * 28.0 + 40.0;
    let max_h = (ui.ctx().content_rect().height() - 90.0).max(160.0);
    if need > max_h {
        ScrollArea::vertical()
            .max_height(max_h)
            .show(ui, |ui| body(ui, set, time, new_field, time_ref));
    } else {
        body(ui, set, time, new_field, time_ref);
    }
}

fn body(
    ui: &mut Ui,
    set: &mut ColumnSet,
    time: &mut TimeFormat,
    new_field: &mut String,
    time_ref: &mut Option<(u64, f64)>,
) {
    section(ui, "Columns");
    let n = set.specs().len();
    for i in 0..n {
        let spec = &set.specs()[i];
        let key = ColKey::parse(&spec.key);
        let (mut visible, custom) = (spec.visible, matches!(key, Some(ColKey::Field(_))));
        let title = key.as_ref().map_or("?", |k| k.title()).to_owned();
        ui.horizontal(|ui| {
            ui.set_width(MENU_W);
            if ui.checkbox(&mut visible, title).changed() {
                set.toggle(i);
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if custom {
                    if mini_button(ui, MiniGlyph::Cross, "Remove column", true).clicked() {
                        set.remove(i);
                    }
                } else {
                    // keep the up/down buttons in one column on every row
                    ui.allocate_space(vec2(MINI_BUTTON, MINI_BUTTON));
                }
                if mini_button(ui, MiniGlyph::Down, "Move down", i + 1 < n).clicked() {
                    set.move_by(i, 1);
                }
                if mini_button(ui, MiniGlyph::Up, "Move up", i > 0).clicked() {
                    set.move_by(i, -1);
                }
            });
        });
    }
    ui.add_space(spacing::XS);
    ui.horizontal(|ui| {
        let v = ui.visuals_mut();
        v.widgets.inactive.bg_stroke = Stroke::new(1.0, Palette::border());
        v.extreme_bg_color = Palette::bg();
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            let add = ui.button("Add").clicked();
            let w = ui.available_width();
            let edit = ui.add(
                text_field(new_field)
                    .hint_text("Add field, e.g. ip.ttl")
                    .desired_width(w.max(80.0)),
            );
            let enter = edit.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
            if (add || enter) && set.add_field(new_field) {
                new_field.clear();
            }
        });
    });
    ui.separator();
    section(ui, "Time display");
    for f in TimeFormat::ALL {
        ui.radio_value(time, f, f.label());
    }
    ui.add_enabled_ui(time_ref.is_some(), |ui| {
        if ui.button("Clear time reference").clicked() {
            *time_ref = None;
        }
    });
    ui.separator();
    ui.add_enabled_ui(!set.is_default() || *time != TimeFormat::default(), |ui| {
        if ui.button("Reset columns and time").clicked() {
            *set = ColumnSet::default();
            *time = TimeFormat::default();
            ui.close();
        }
    });
}

fn section(ui: &mut Ui, title: &str) {
    ui.label(RichText::new(title).small().color(Palette::muted()));
}
