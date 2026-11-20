//! Cell and header drawing for the packet table.

use eframe::egui::{
    self, Align, Color32, CursorIcon, Layout, Rect, RichText, Sense, Stroke, Ui, pos2,
};
use egui_extras::{Column, TableBuilder, TableRow};
use wl_kit::table::{CELL_PAD, sort_arrow};
use wl_kit::widgets::{PROTOCOL_PILL_W, elided_label, protocol_pill_centered};
use wl_model::PacketRow;

use crate::packets::columns::{Col, ColKey};
use crate::packets::custom_cols::CustomCols;
use crate::packets::kit::{Palette, protocol_color, row_h};
use crate::packets::time_format::{self, TimeCtx, TimeFormat};

/// Everything a cell needs besides its row.
pub struct CellCtx<'a> {
    pub time: TimeCtx,
    pub custom: &'a CustomCols,
}

pub fn col_widths(key: &ColKey, fmt: TimeFormat) -> (f32, f32) {
    match key {
        ColKey::Std(Col::Time) => fmt.widths(),
        ColKey::Std(c) => c.widths(),
        ColKey::Field(_) => (110.0, 60.0),
    }
}

/// Header text (the Time column is named after the active time format).
pub fn col_title(key: &ColKey, fmt: TimeFormat) -> &str {
    match key {
        ColKey::Std(Col::Time) => fmt.column_title(),
        k => k.title(),
    }
}

pub fn build_table<'a>(
    ui: &'a mut Ui,
    table_h: f32,
    cols: &[ColKey],
    fmt: TimeFormat,
) -> TableBuilder<'a> {
    let salt: String = cols.iter().map(ColKey::key).collect::<Vec<_>>().join(",");
    let mut tb = TableBuilder::new(ui)
        .id_salt(("pkt_cols", fmt, salt))
        .striped(true)
        .animate_scrolling(false)
        .resizable(true)
        .sense(Sense::click())
        .cell_layout(Layout::left_to_right(Align::Center))
        .min_scrolled_height(0.0)
        .max_scroll_height((table_h - row_h() - 4.0).max(row_h()));
    for (i, c) in cols.iter().enumerate() {
        let (w, min) = col_widths(c, fmt);
        tb = tb.column(if i + 1 == cols.len() {
            Column::remainder().at_least(min).clip(true)
        } else {
            Column::initial(w).at_least(min).clip(true)
        });
    }
    tb
}

pub fn text_cell(ui: &mut Ui, text: &str) -> egui::Response {
    elided_label(ui, text, ui.available_width())
}

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

fn accent_bar(ui: &Ui, color: Color32) {
    let r = ui.max_rect();
    let bar = Rect::from_min_max(r.left_top(), pos2(r.left() + 3.0, r.bottom()));
    ui.painter().rect_filled(bar, 0.0, color);
}

fn ref_tint(ui: &Ui) {
    let r = ui
        .max_rect()
        .expand2(egui::vec2(ui.spacing().item_spacing.x / 2.0, 0.0));
    let c = wl_kit::theme::tint(Palette::accent(), 38);
    ui.painter().rect_filled(r, 0.0, c);
}

pub fn cell(row: &mut TableRow<'_, '_>, key: &ColKey, r: &PacketRow, cx: &CellCtx) {
    let col = match key {
        ColKey::Std(c) => *c,
        ColKey::Field(f) => {
            row.col(|ui| {
                if cx.time.reference.is_some_and(|(no, _)| no == r.no) {
                    ref_tint(ui);
                }
                ui.add_space(CELL_PAD);
                text_cell(ui, cx.custom.get(f, r.no).unwrap_or(""));
            });
            return;
        }
    };
    row.col(|ui| {
        if !col.numeric() {
            ui.add_space(CELL_PAD);
        }
        if cx.time.reference.is_some_and(|(no, _)| no == r.no) {
            ref_tint(ui);
        }
        match col {
            Col::No => {
                accent_bar(ui, protocol_color(&r.protocol));
                num_cell(ui, &r.no.to_string());
            }
            Col::Time => num_cell(ui, &time_format::text(r, &cx.time)),
            Col::Length => num_cell(ui, &r.len.to_string()),
            Col::Source => {
                text_cell(ui, &r.src);
            }
            Col::Destination => {
                text_cell(ui, &r.dst);
            }
            Col::Protocol => {
                protocol_pill_centered(ui, &r.protocol, PROTOCOL_PILL_W);
            }
            Col::Info => {
                text_cell(ui, &r.info);
            }
        }
    });
}

/// Draws a header cell; the response is clicked for sorting (built-in columns only) and
/// carries the right-click column menu.
pub fn header_cell(
    ui: &mut Ui,
    key: &ColKey,
    title: &str,
    sort: Option<(Col, bool)>,
) -> egui::Response {
    let col = match key {
        ColKey::Std(c) => Some(*c),
        ColKey::Field(_) => None,
    };
    let (numeric, centered) = col.map_or((false, false), |c| (c.numeric(), c.centered()));
    let rect = ui.max_rect();
    let resp = ui.interact(rect, ui.scope_id().with(title), Sense::click());
    ui.painter().line_segment(
        [
            pos2(rect.left(), rect.bottom()),
            pos2(rect.right(), rect.bottom()),
        ],
        Stroke::new(1.0, Palette::border()),
    );
    let arrow = sort.filter(|s| Some(s.0) == col).map(|s| s.1);
    let color = if resp.hovered() || arrow.is_some() {
        Palette::text()
    } else {
        Palette::muted()
    };
    let layout = if numeric {
        Layout::right_to_left(Align::Center)
    } else {
        Layout::left_to_right(Align::Center)
    };
    ui.with_layout(layout, |ui| {
        let label = RichText::new(title).small().strong().color(color);
        if centered {
            // Label centered like the pill below it; the sort arrow trails it (no text jump).
            let font = egui::TextStyle::Small.resolve(ui.style());
            let w = ui
                .painter()
                .layout_no_wrap(title.to_owned(), font, color)
                .size()
                .x;
            ui.add_space(((ui.available_width() - w) / 2.0).max(CELL_PAD));
            ui.add(egui::Label::new(label).truncate().selectable(false));
            arrow_icon(ui, arrow);
            return;
        }
        ui.add_space(CELL_PAD);
        if numeric {
            arrow_icon(ui, arrow);
            ui.add(egui::Label::new(label).truncate().selectable(false));
        } else {
            ui.add(egui::Label::new(label).truncate().selectable(false));
            arrow_icon(ui, arrow);
        }
    });
    resp.on_hover_cursor(CursorIcon::PointingHand)
}

fn arrow_icon(ui: &mut Ui, asc: Option<bool>) {
    if let Some(asc) = asc {
        sort_arrow(ui, asc, Palette::accent());
    }
}
