//! "Saved" menu of the filter bar: apply, rename, delete and save the current filter.

use eframe::egui::{Button, Key, RichText, TextEdit, Ui};
use wl_kit::widgets::mini_button::{MiniGlyph, mini_button};

use crate::packets::filter_presets::Presets;
use crate::packets::kit::Palette;

#[derive(Default)]
pub struct MenuEdit {
    new_name: String,
    renaming: Option<(usize, String)>,
}

/// Returns the expression of the preset the user picked.
pub fn menu(
    ui: &mut Ui,
    presets: &mut Presets,
    current: &str,
    edit: &mut MenuEdit,
) -> Option<String> {
    let mut chosen = None;
    ui.menu_button("Saved", |ui| {
        ui.set_min_width(240.0);
        if presets.items().is_empty() {
            ui.label(
                RichText::new("No saved filters yet")
                    .small()
                    .color(Palette::muted()),
            );
        }
        let mut remove = None;
        for i in 0..presets.items().len() {
            ui.horizontal(|ui| {
                if edit.renaming.as_ref().is_some_and(|(r, _)| *r == i) {
                    rename_row(ui, presets, i, edit);
                    return;
                }
                let item = &presets.items()[i];
                let hit = ui
                    .add(Button::new(&item.name).frame(false))
                    .on_hover_text(&item.expr);
                if hit.clicked() {
                    chosen = Some(item.expr.clone());
                    ui.close();
                }
                if ui.small_button("Rename").clicked() {
                    edit.renaming = Some((i, item.name.clone()));
                }
                if mini_button(ui, MiniGlyph::Cross, "Delete", true).clicked() {
                    remove = Some(i);
                }
            });
        }
        if let Some(i) = remove {
            presets.remove(i);
        }
        ui.separator();
        save_row(ui, presets, current, edit);
    });
    chosen
}

fn rename_row(ui: &mut Ui, presets: &mut Presets, i: usize, edit: &mut MenuEdit) {
    let Some((_, name)) = edit.renaming.as_mut() else {
        return;
    };
    let field = ui.add(TextEdit::singleline(name).desired_width(150.0));
    field.request_focus();
    let done = ui.input(|k| k.key_pressed(Key::Enter));
    if ui.input(|k| k.key_pressed(Key::Escape)) || done && presets.rename(i, name) {
        edit.renaming = None;
    }
}

fn save_row(ui: &mut Ui, presets: &mut Presets, current: &str, edit: &mut MenuEdit) {
    ui.horizontal(|ui| {
        ui.add(
            TextEdit::singleline(&mut edit.new_name)
                .hint_text("Name for the current filter")
                .desired_width(150.0),
        );
        let ready = !edit.new_name.trim().is_empty() && !current.trim().is_empty();
        if ui.add_enabled(ready, Button::new("Save")).clicked()
            && presets.save(&edit.new_name, current)
        {
            edit.new_name.clear();
        }
    });
}
