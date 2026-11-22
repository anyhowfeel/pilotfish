//! Master table: virtualized, sortable, one row per HTTP exchange or TLS session.

use wl_kit::egui::{Align, Layout, ScrollArea, Ui, vec2};
use wl_kit::table::{HEADER_H, num_cell};
use wl_kit::theme::row_h;

use super::columns::Cols;
use super::model::{Data, RowRef, Sel, SortCol, sel_of};
use super::table_cells::{http_cells, time_text, tls_cells};
use crate::overview::{SortState, sort_header};

pub struct TableIn<'a> {
    pub data: Data<'a>,
    pub rows: &'a [RowRef],
    pub sort: SortState<SortCol>,
    pub selected: Option<Sel>,
    pub max_ms: f64,
    pub scroll_to: Option<usize>,
}

#[derive(Default)]
pub struct TableOut {
    pub sort: Option<SortCol>,
    pub picked: Option<usize>,
}

/// (title, sort column, right aligned) of every header, optional ones flagged by `Cols`.
fn heads(c: Cols) -> Vec<(&'static str, SortCol, bool)> {
    let mut h = Vec::new();
    if c.time {
        h.push(("Time", SortCol::Time, true));
    }
    h.extend([
        ("Method", SortCol::Method, false),
        ("Host", SortCol::Host, false),
        ("URL", SortCol::Path, false),
        ("Status", SortCol::Status, false),
    ]);
    if c.kind {
        h.push(("Type", SortCol::Type, false));
    }
    if c.size {
        h.push(("Size", SortCol::Size, true));
    }
    if c.latency {
        h.push(("Latency", SortCol::Latency, true));
    }
    h
}

pub fn master_table(ui: &mut Ui, t: &TableIn) -> TableOut {
    let mut out = TableOut::default();
    let cols = Cols::for_width(ui.available_width());
    let table_w = ui.available_width().max(cols.min_width());
    // A horizontal scrollbar (only when even the minimal set does not fit) sits below the content.
    let bar = if table_w > ui.available_width() {
        ui.spacing().scroll.allocated_width() + 1.0
    } else {
        0.0
    };
    let avail_h = (ui.available_height() - bar).max(HEADER_H + row_h());
    ui.style_mut().interaction.selectable_labels = false;
    ScrollArea::horizontal()
        .id_salt("web_hscroll")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.allocate_ui_with_layout(
                vec2(table_w, avail_h),
                Layout::top_down(Align::Min),
                |ui| {
                    let mut tb = cols
                        .build()
                        .build(ui)
                        .auto_shrink([false, false])
                        .max_scroll_height((avail_h - HEADER_H).max(row_h()));
                    if let Some(i) = t.scroll_to {
                        tb = tb.scroll_to_row(i, Some(Align::Center));
                    }
                    tb.header(HEADER_H, |mut h| {
                        for (title, col, right) in heads(cols) {
                            h.col(|ui| {
                                if sort_header(ui, title, col, &t.sort, right) {
                                    out.sort = Some(col);
                                }
                            });
                        }
                    })
                    .body(|body| {
                        body.rows(row_h(), t.rows.len(), |mut row| {
                            let r = t.rows[row.index()];
                            row.set_selected(t.selected == Some(sel_of(&t.data, r)));
                            let start = match r {
                                RowRef::Http(i) => t.data.ex[i as usize].start_rel,
                                RowRef::Tls(i) => t.data.tls[i as usize].start_rel,
                            };
                            if cols.time {
                                row.col(|ui| num_cell(ui, &time_text(start)));
                            }
                            match r {
                                RowRef::Http(i) => {
                                    http_cells(&mut row, &t.data.ex[i as usize], t.max_ms, cols)
                                }
                                RowRef::Tls(i) => {
                                    tls_cells(&mut row, &t.data.tls[i as usize], cols)
                                }
                            }
                            if row.response().clicked() {
                                out.picked = Some(row.index());
                            }
                        });
                    });
                },
            );
        });
    out
}
