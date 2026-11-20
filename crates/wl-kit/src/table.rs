//! Helpers over `egui_extras::TableBuilder`: striped, aligned, row_h() rows.

use eframe::egui::{
    self, Align, Color32, Layout, Response, RichText, Sense, Shape, Ui, Vec2, pos2,
};
use egui_extras::{Column, TableBuilder};

use crate::theme::{Palette, spacing};

pub use egui_extras::TableBody;

/// Shared horizontal inset inside table header and body cells so columns align to the pixel.
pub const CELL_PAD: f32 = spacing::SM;

/// Column spec builder. Columns are non-resizable by default.
#[derive(Default)]
pub struct TableCols(Vec<Column>);

impl TableCols {
    pub fn new() -> Self {
        Self::default()
    }
    /// Fixed-width column (use for text/identifiers).
    pub fn fixed(mut self, w: f32) -> Self {
        self.0.push(Column::exact(w).clip(true));
        self
    }
    /// Fixed-width numeric column (pair with `num_cell`).
    pub fn num(self, w: f32) -> Self {
        self.fixed(w)
    }
    /// Flexible column with a minimum width.
    pub fn flex(mut self, min: f32) -> Self {
        self.0.push(Column::remainder().at_least(min).clip(true));
        self
    }
    pub fn build<'a>(self, ui: &'a mut Ui) -> TableBuilder<'a> {
        let mut t = TableBuilder::new(ui)
            .striped(true)
            .resizable(false)
            .sense(egui::Sense::click())
            .min_scrolled_height(0.0)
            .cell_layout(Layout::left_to_right(Align::Center));
        for c in self.0 {
            t = t.column(c);
        }
        t
    }
}

/// Header height.
pub const HEADER_H: f32 = crate::theme::ROW_H + 4.0;

/// Painted sort direction triangle (pointing up for ascending, down for descending).
pub fn sort_arrow(ui: &mut Ui, asc: bool, color: Color32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(10.0), Sense::hover());
    let c = rect.center();
    let d = if asc { -1.0 } else { 1.0 };
    let pts = vec![
        pos2(c.x - 3.5, c.y - 2.0 * d),
        pos2(c.x + 3.5, c.y - 2.0 * d),
        pos2(c.x, c.y + 2.5 * d),
    ];
    ui.painter()
        .add(Shape::convex_polygon(pts, color, egui::Stroke::NONE));
}

/// Left-aligned header label; `right` for numeric columns.
pub fn header_cell(ui: &mut Ui, text: &str, right: bool) {
    let rt = RichText::new(text).small().strong().color(Palette::muted());
    if right {
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.add_space(CELL_PAD);
            ui.add(egui::Label::new(rt).truncate().selectable(false))
        });
    } else {
        ui.add_space(CELL_PAD);
        ui.add(egui::Label::new(rt).truncate().selectable(false));
    }
}

/// Left-aligned truncated text cell.
pub fn text_cell(ui: &mut Ui, text: &str) -> Response {
    ui.add_space(CELL_PAD);
    ui.add(egui::Label::new(text).truncate().selectable(false))
}

/// Right-aligned monospace numeric cell.
pub fn num_cell(ui: &mut Ui, text: &str) {
    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
        ui.add_space(CELL_PAD);
        ui.add(
            egui::Label::new(RichText::new(text).monospace())
                .truncate()
                .selectable(false),
        );
    });
}

/// Padding-aware: inset cell content so text/pills align with headers.
pub fn cell_pad(ui: &mut Ui) {
    ui.add_space(CELL_PAD);
}

/// Mark the row selected.
pub fn selectable_row(row: &mut egui_extras::TableRow<'_, '_>, selected: bool) {
    row.set_selected(selected);
}
