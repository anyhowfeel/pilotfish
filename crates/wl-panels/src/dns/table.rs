//! Virtualised, sortable table of DNS transactions with responsive columns.

use egui_extras::TableRow;
use wl_kit::egui::{Align, Layout, RichText, Ui};
use wl_kit::format;
use wl_kit::table::{HEADER_H, cell_pad, num_cell, text_cell};
use wl_kit::theme::{Palette, row_h};
use wl_kit::widgets::{PillStyle, Severity, pill};
use wl_model::{DnsQuery, Rcode};

use super::cols::{Cols, RCODE_W};
use super::model::{SortCol, class_of, ms_text};
use crate::overview::{SortState, sort_header};

pub struct TableIn<'a> {
    pub all: &'a [DnsQuery],
    pub rows: &'a [u32],
    pub sort: SortState<SortCol>,
    pub selected: Option<u64>,
    pub scroll_to: Option<usize>,
}

#[derive(Default)]
pub struct TableOut {
    pub sort: Option<SortCol>,
    pub picked: Option<usize>,
}

/// Severity token of a response (None = no response, drawn neutral).
pub fn rcode_color(q: &DnsQuery) -> wl_kit::egui::Color32 {
    match class_of(q) {
        0 => Severity::Ok.color(),
        1 => Severity::Warning.color(),
        2 => Severity::Critical.color(),
        _ => Palette::muted(),
    }
}

pub fn rcode_label(q: &DnsQuery) -> String {
    q.rcode
        .map_or_else(|| "No response".to_owned(), Rcode::label)
}

fn muted(ui: &mut Ui, text: &str) {
    cell_pad(ui);
    ui.label(RichText::new(text).color(Palette::muted()));
}

fn cells(row: &mut TableRow<'_, '_>, q: &DnsQuery, c: Cols) {
    if c.wide {
        row.col(|ui| num_cell(ui, &q.frame.to_string()));
    }
    row.col(|ui| num_cell(ui, &format::time_rel(q.rel)));
    if c.basic {
        row.col(|ui| {
            text_cell(ui, &q.client).on_hover_text(&q.client);
        });
    }
    if c.server {
        row.col(|ui| {
            text_cell(ui, &q.server).on_hover_text(&q.server);
        });
    }
    row.col(|ui| {
        text_cell(ui, &q.name).on_hover_text(&q.name);
    });
    if c.basic {
        row.col(|ui| muted(ui, &q.qtype));
    }
    row.col(|ui| {
        cell_pad(ui);
        pill(
            ui,
            &rcode_label(q),
            rcode_color(q),
            PillStyle::column(RCODE_W - 16.0),
        );
    });
    if c.answers {
        row.col(|ui| {
            let t = q.answers.join(", ");
            text_cell(ui, &t).on_hover_text(&t);
        });
    }
    row.col(|ui| match q.rtt_ms {
        Some(ms) => num_cell(ui, &ms_text(ms)),
        None => {
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.add_space(wl_kit::table::CELL_PAD);
                ui.label(RichText::new("-").color(Palette::muted()));
            });
        }
    });
    if c.wide {
        row.col(|ui| {
            if q.retransmission {
                cell_pad(ui);
                pill(
                    ui,
                    "retx",
                    Severity::Warning.color(),
                    PillStyle::badge().with_dot(false),
                )
                .on_hover_text("Query was retransmitted");
            }
        });
    }
}

pub fn table(ui: &mut Ui, t: &TableIn) -> TableOut {
    let mut out = TableOut::default();
    let cols = Cols::for_width(ui.available_width());
    ui.style_mut().interaction.selectable_labels = false;
    let avail_h = ui.available_height().max(HEADER_H + row_h());
    let mut tb = cols
        .build()
        .build(ui)
        .auto_shrink([false, false])
        .max_scroll_height((avail_h - HEADER_H).max(row_h()));
    if let Some(i) = t.scroll_to {
        tb = tb.scroll_to_row(i, Some(Align::Center));
    }
    tb.header(HEADER_H, |mut h| {
        for (title, col, right) in cols.heads() {
            h.col(|ui| match col {
                Some(c) => {
                    if sort_header(ui, title, c, &t.sort, right) {
                        out.sort = Some(c);
                    }
                }
                None => wl_kit::table::header_cell(ui, title, right),
            });
        }
    })
    .body(|body| {
        body.rows(row_h(), t.rows.len(), |mut row| {
            let q = &t.all[t.rows[row.index()] as usize];
            row.set_selected(t.selected == Some(q.frame));
            cells(&mut row, q, cols);
            if row.response().clicked() {
                out.picked = Some(row.index());
            }
        });
    });
    out
}

#[cfg(test)]
#[path = "table_tests.rs"]
mod tests;
