//! Right-click menu of a dissection-tree node: filter actions, "Apply as Column", copy.

use eframe::egui::Ui;
use wl_model::DetailNode;

use crate::features::{detail_filter_menu, extract_filter_candidate};
use crate::packets::tree_model::{self as model, FlatRow};

/// What the user picked.
#[derive(Default)]
pub struct Out {
    pub filter: Option<String>,
    pub column: Option<String>,
}

pub fn show(
    ui: &mut Ui,
    r: &FlatRow,
    parent_layer: Option<&str>,
    current_filter: &str,
    path: &dyn Fn() -> String,
    out: &mut Out,
) {
    let node = DetailNode {
        label: r.label.clone(),
        range: r.range,
        children: Vec::new(),
    };
    if let Some(cand) = extract_filter_candidate(&node, parent_layer, None) {
        if let Some(expr) = detail_filter_menu(ui, &cand, current_filter) {
            out.filter = Some(expr);
        }
        if ui
            .button("Apply as Column")
            .on_hover_text(format!("Show {} as a packet-list column", cand.field))
            .clicked()
        {
            out.column = Some(cand.field.clone());
            ui.close();
        }
        ui.separator();
    }
    if ui.button("Copy value").clicked() {
        ui.ctx().copy_text(model::value_of(&r.label).to_owned());
        ui.close();
    }
    if ui.button("Copy label").clicked() {
        ui.ctx().copy_text(r.label.clone());
        ui.close();
    }
    if ui.button("Copy path").clicked() {
        ui.ctx().copy_text(path());
        ui.close();
    }
}
