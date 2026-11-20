//! Quick-filter row: toggle chips for the busiest protocols, the rest + presets in a menu.

use eframe::egui::{
    self, Align, Button, Layout, Popup, PopupCloseBehavior, RichText, SetOpenCommand, Ui,
};
use wl_kit::format::count;
use wl_kit::widgets::{TOGGLE_CHIP_H, menu_chip, menu_chip_width, toggle_chip, toggle_chip_width};

use crate::packets::kit::{Palette, spacing};
use crate::packets::quick_filter::{
    PRESETS, QuickChip, fit_count, is_active, toggle, toggle_preset,
};

const GAP: f32 = spacing::XS + 2.0;
const MENU_LABEL: &str = "Quick filters";

/// Draws the row for filter `text`; returns the new filter text when a chip/menu item was used.
pub fn ui(ui: &mut Ui, text: &str, chips: &[QuickChip], open_now: bool) -> Option<String> {
    let mut chosen = None;
    let labels: Vec<String> = chips.iter().map(|c| count(c.count)).collect();
    let widths: Vec<f32> = chips
        .iter()
        .zip(&labels)
        .map(|(c, n)| toggle_chip_width(ui, &c.label, Some(n)))
        .collect();
    let menu_w = menu_chip_width(ui, MENU_LABEL);
    let shown = fit_count(&widths, ui.available_width(), GAP, menu_w + GAP);
    ui.allocate_ui_with_layout(
        egui::vec2(ui.available_width(), TOGGLE_CHIP_H),
        Layout::left_to_right(Align::Center),
        |ui| {
            ui.spacing_mut().item_spacing.x = GAP;
            let hidden_on = chips[shown..].iter().any(|c| is_active(text, &c.expr));
            let preset_on = PRESETS.iter().any(|p| text.trim() == p.1);
            let menu = menu_chip(ui, MENU_LABEL, hidden_on || preset_on);
            let mut popup = Popup::menu(&menu);
            if open_now {
                popup = popup.open_memory(SetOpenCommand::Bool(true));
            }
            popup
                .close_behavior(PopupCloseBehavior::CloseOnClickOutside)
                .show(|ui| {
                    ui.set_min_width(220.0);
                    ui.spacing_mut().interact_size.y = 24.0;
                    menu_items(ui, text, &chips[shown..], &labels[shown..], &mut chosen);
                });
            for (c, n) in chips[..shown].iter().zip(&labels) {
                if toggle_chip(ui, is_active(text, &c.expr), &c.label, Some(n)).clicked() {
                    chosen = Some(toggle(text, &c.expr));
                }
            }
            if chips.is_empty() {
                ui.label(
                    RichText::new("No protocols yet")
                        .small()
                        .color(Palette::muted()),
                );
            }
        },
    );
    chosen
}

fn menu_items(
    ui: &mut Ui,
    text: &str,
    rest: &[QuickChip],
    labels: &[String],
    chosen: &mut Option<String>,
) {
    if !rest.is_empty() {
        section(ui, "More protocols");
        for (c, n) in rest.iter().zip(labels) {
            let on = is_active(text, &c.expr);
            if ui
                .add(Button::selectable(on, format!("{}   {n}", c.label)))
                .clicked()
            {
                *chosen = Some(toggle(text, &c.expr));
            }
        }
        ui.separator();
    }
    section(ui, "Presets");
    for (label, expr) in PRESETS {
        let on = text.trim() == expr;
        if ui.add(Button::selectable(on, label)).clicked() {
            *chosen = Some(toggle_preset(text, expr));
        }
    }
    if !text.trim().is_empty() {
        ui.separator();
        if ui.button("Clear filter").clicked() {
            *chosen = Some(String::new());
            ui.close();
        }
    }
}

fn section(ui: &mut Ui, title: &str) {
    ui.label(RichText::new(title).small().color(Palette::muted()));
}
