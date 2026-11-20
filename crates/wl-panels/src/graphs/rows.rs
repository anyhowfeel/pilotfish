//! The series editor: a header and one aligned row per series (swatch, name, filter with
//! autocomplete, metric, totals, visibility, remove).

use std::sync::Arc;

use wl_kit::egui::{
    self, Align, Align2, Color32, ComboBox, CornerRadius, CursorIcon, FontId, Rect, RichText,
    Sense, Stroke, StrokeKind, Ui, UiBuilder, pos2, vec2,
};
use wl_kit::format;
use wl_kit::theme::Palette;
use wl_kit::widgets::{Glyph, icon_button, paint_elided, text_field};
use wl_model::IoSeries;

use super::cols::{Cols, ROW_H};
use super::metric::{Metric, totals, window_totals};
use super::series::SeriesDef;
use crate::features::FilterAutocomplete;

/// What the user did to a row this frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowEdit {
    Remove,
    CycleColor,
    None,
}

/// Window the totals column reports instead of the whole capture.
#[derive(Debug, Clone, Copy)]
pub struct WindowSel {
    pub from: f64,
    pub to: f64,
    pub interval: f64,
}

pub fn header(ui: &mut Ui, window: bool) {
    let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), 18.0), Sense::hover());
    let c = Cols::new(Rect::from_min_size(rect.min, vec2(rect.width(), ROW_H)));
    let p = ui.painter();
    let font = FontId::proportional(11.5);
    let total = if window { "Window total" } else { "Total" };
    let mut heads = vec![
        (c.name, "Name", Align2::LEFT_CENTER),
        (c.filter, "Display filter", Align2::LEFT_CENTER),
        (c.metric, "Metric", Align2::LEFT_CENTER),
    ];
    heads.extend(c.total.map(|t| (t, total, Align2::RIGHT_CENTER)));
    for (col, text, align) in heads {
        let x = if align == Align2::RIGHT_CENTER {
            col.right()
        } else {
            col.left()
        };
        p.text(
            pos2(x, rect.center().y),
            align,
            text,
            font.clone(),
            Palette::muted(),
        );
    }
}

pub struct RowCtx<'a> {
    pub index: usize,
    pub data: Option<&'a Arc<IoSeries>>,
    pub window: Option<WindowSel>,
    pub autocomplete: &'a mut FilterAutocomplete,
}

pub fn row(ui: &mut Ui, def: &mut SeriesDef, cx: RowCtx<'_>) -> RowEdit {
    let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), ROW_H), Sense::hover());
    let c = Cols::new(rect);
    #[cfg(test)]
    ui.data_mut(|d| d.insert_temp(egui::Id::NULL.with(("wl_graph_row", cx.index)), c));
    let mut edit = RowEdit::None;
    let error = cx.data.and_then(|d| d.error.as_deref());
    let (text, color) = total_text(def, cx.data, cx.window);
    let tip = c.total.is_none().then_some(text.as_str());
    if swatch(ui, c.swatch, def, tip).clicked() {
        edit = RowEdit::CycleColor;
    }
    ui.scope_builder(UiBuilder::new().max_rect(c.name), |ui| {
        ui.add_enabled_ui(def.visible, |ui| {
            let hint = RichText::new(def.display_name()).color(Palette::muted());
            ui.add_sized(c.name.size(), text_field(&mut def.name).hint_text(hint));
        });
    });
    filter_field(ui, c.filter, def, error.is_some(), cx.autocomplete);
    metric_combo(ui, c.metric, cx.index, def);
    if let Some(rect) = c.total {
        totals_cell(ui, rect, &text, color, error);
    }
    let (eye, tip) = if def.visible {
        (Glyph::Eye, "Hide series")
    } else {
        (Glyph::EyeOff, "Show series")
    };
    if button_at(ui, c.eye, tip, eye) {
        def.visible = !def.visible;
    }
    if button_at(ui, c.remove, "Remove series", Glyph::Cross) {
        edit = RowEdit::Remove;
    }
    edit
}

fn button_at(ui: &mut Ui, rect: Rect, tip: &str, glyph: Glyph) -> bool {
    ui.scope_builder(UiBuilder::new().max_rect(rect), |ui| {
        icon_button(ui, tip, glyph).clicked()
    })
    .inner
}

/// Colour dot; a hollow ring while the series is hidden. Click cycles the palette slot.
/// `totals` (shown when the row has no totals column) joins the tooltip.
fn swatch(ui: &mut Ui, rect: Rect, def: &SeriesDef, totals: Option<&str>) -> egui::Response {
    let id = ui.scope_id().with(("swatch", rect.min.y as i32));
    let tip = match totals {
        Some(t) => format!("Change colour\nTotal: {t}"),
        None => "Change colour".to_owned(),
    };
    let resp = ui
        .interact(rect, id, Sense::click())
        .on_hover_cursor(CursorIcon::PointingHand)
        .on_hover_text(tip);
    let color = Palette::series(def.color);
    let r = if resp.hovered() { 8.0 } else { 7.0 };
    if def.visible {
        ui.painter().circle_filled(rect.center(), r, color);
    } else {
        ui.painter().circle_stroke(
            rect.center(),
            r - 1.0,
            Stroke::new(2.0, color.gamma_multiply(0.6)),
        );
    }
    resp
}

fn filter_field(
    ui: &mut Ui,
    rect: Rect,
    def: &mut SeriesDef,
    error: bool,
    auto: &mut FilterAutocomplete,
) {
    ui.scope_builder(UiBuilder::new().max_rect(rect), |ui| {
        ui.add_enabled_ui(def.visible, |ui| {
            let hint = RichText::new("all packets").color(Palette::muted());
            let resp = ui.add_sized(rect.size(), text_field(&mut def.filter).hint_text(hint));
            auto.ui(ui, &mut def.filter, &resp);
            if error {
                ui.painter().rect_stroke(
                    rect,
                    CornerRadius::same(4),
                    Stroke::new(1.5, Palette::danger()),
                    StrokeKind::Inside,
                );
            }
            // Queried on commit only: every keystroke would restart a pass over the file.
            if resp.lost_focus() {
                def.commit();
            }
        });
    });
}

fn metric_combo(ui: &mut Ui, rect: Rect, index: usize, def: &mut SeriesDef) {
    ui.scope_builder(UiBuilder::new().max_rect(rect), |ui| {
        ui.add_enabled_ui(def.visible, |ui| {
            ComboBox::from_id_salt(("graph_metric", index))
                .selected_text(def.metric.label())
                .width(rect.width() - 2.0 * ui.spacing().button_padding.x - 16.0)
                .show_ui(ui, |ui| {
                    for m in Metric::ALL {
                        ui.selectable_value(&mut def.metric, m, m.label());
                    }
                });
        });
    });
}

/// What the totals column says for one series: whole-capture totals, or the selected window's.
fn total_text(
    def: &SeriesDef,
    data: Option<&Arc<IoSeries>>,
    window: Option<WindowSel>,
) -> (String, Color32) {
    match data {
        _ if !def.visible => ("hidden".to_owned(), Palette::muted()),
        Some(d) if d.error.is_some() => ("invalid filter".into(), Palette::danger()),
        Some(d) => {
            let ((n, b), c) = match window {
                Some(w) => (
                    window_totals(d, w.interval, w.from, w.to),
                    Palette::accent(),
                ),
                None => (totals(d), Palette::text()),
            };
            (
                format!("{} \u{b7} {}", format::count(n), format::bytes(b)),
                c,
            )
        }
        None => ("\u{2026}".into(), Palette::muted()),
    }
}

fn totals_cell(ui: &mut Ui, rect: Rect, text: &str, color: Color32, error: Option<&str>) {
    let id = ui.scope_id().with(("total", rect.min.y as i32));
    let resp = ui.interact(rect, id, Sense::hover());
    let font = egui::TextStyle::Monospace.resolve(ui.style());
    paint_elided(ui.painter(), rect, text, font, color, Align::Max);
    if let Some(e) = error {
        resp.on_hover_text(e);
    }
}

/// Footer button adding a series; returns true when clicked.
pub fn add_button(ui: &mut Ui, enabled: bool) -> bool {
    ui.add_enabled_ui(enabled, |ui| {
        let text = RichText::new("+ Add series").color(Palette::text());
        let resp = ui.add_sized(vec2(112.0, ROW_H), egui::Button::new(text));
        #[cfg(test)]
        ui.data_mut(|d| d.insert_temp(egui::Id::NULL.with("wl_graph_add"), resp.rect));
        resp.clicked()
    })
    .inner
}
