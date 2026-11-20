//! Virtualised, sortable table of exported objects with responsive columns.

use wl_kit::egui::{Align, RichText, Ui};
use wl_kit::format;
use wl_kit::table::{HEADER_H, TableCols, cell_pad, num_cell, text_cell};
use wl_kit::theme::{Palette, row_h};
use wl_kit::widgets::Severity;
use wl_model::ExportObject;

use super::model::{LARGE, SortCol};
use crate::overview::{SortState, sort_header};

const PACKET_W: f32 = 64.0;
const TYPE_W: f32 = 168.0;
const SIZE_W: f32 = 88.0;
const FLEX_MIN: f32 = 110.0;
const PACKET_FROM: f32 = 480.0;
const HOST_FROM: f32 = 600.0;
const TYPE_FROM: f32 = 800.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cols {
    pub packet: bool,
    pub host: bool,
    pub kind: bool,
}

impl Cols {
    pub fn for_width(w: f32) -> Self {
        Self {
            packet: w >= PACKET_FROM,
            host: w >= HOST_FROM,
            kind: w >= TYPE_FROM,
        }
    }

    fn build(self) -> TableCols {
        let mut t = TableCols::new();
        if self.packet {
            t = t.num(PACKET_W);
        }
        if self.host {
            t = t.flex(FLEX_MIN);
        }
        t = t.flex(FLEX_MIN);
        if self.kind {
            t = t.fixed(TYPE_W);
        }
        t.num(SIZE_W)
    }

    fn heads(self) -> Vec<(&'static str, SortCol, bool)> {
        let mut h = Vec::new();
        if self.packet {
            h.push(("Packet", SortCol::Packet, true));
        }
        if self.host {
            h.push(("Host", SortCol::Host, false));
        }
        h.push(("Name", SortCol::Name, false));
        if self.kind {
            h.push(("Type", SortCol::Type, false));
        }
        h.push(("Size", SortCol::Size, true));
        h
    }

    #[cfg(test)]
    pub fn min_width(self) -> f32 {
        let n = 2 + usize::from(self.packet) + usize::from(self.host) + usize::from(self.kind);
        let fixed = SIZE_W
            + if self.packet { PACKET_W } else { 0.0 }
            + if self.kind { TYPE_W } else { 0.0 };
        let flex = FLEX_MIN * (1 + usize::from(self.host)) as f32;
        fixed + flex + wl_kit::theme::spacing::SM * (n as f32 - 1.0)
    }
}

pub struct TableIn<'a> {
    pub all: &'a [ExportObject],
    pub rows: &'a [u32],
    pub sort: SortState<SortCol>,
    pub selected: Option<u32>,
}

#[derive(Default)]
pub struct TableOut {
    pub sort: Option<SortCol>,
    pub picked: Option<u32>,
}

fn dash(ui: &mut Ui) {
    cell_pad(ui);
    ui.label(RichText::new("-").color(Palette::muted()));
}

pub fn table(ui: &mut Ui, t: &TableIn) -> TableOut {
    let mut out = TableOut::default();
    let cols = Cols::for_width(ui.available_width());
    ui.style_mut().interaction.selectable_labels = false;
    let h = ui.available_height().max(HEADER_H + row_h());
    cols.build()
        .build(ui)
        .auto_shrink([false, false])
        .max_scroll_height((h - HEADER_H).max(row_h()))
        .header(HEADER_H, |mut hd| {
            for (title, col, right) in cols.heads() {
                hd.col(|ui| {
                    if sort_header(ui, title, col, &t.sort, right) {
                        out.sort = Some(col);
                    }
                });
            }
        })
        .body(|body| {
            body.rows(row_h(), t.rows.len(), |mut row| {
                let o = &t.all[t.rows[row.index()] as usize];
                row.set_selected(t.selected == Some(o.id));
                if cols.packet {
                    row.col(|ui| match o.packet {
                        Some(p) => num_cell(ui, &p.to_string()),
                        None => {
                            ui.with_layout(
                                wl_kit::egui::Layout::right_to_left(Align::Center),
                                |ui| {
                                    ui.add_space(wl_kit::table::CELL_PAD);
                                    ui.label(RichText::new("-").color(Palette::muted()));
                                },
                            );
                        }
                    });
                }
                if cols.host {
                    row.col(|ui| {
                        if o.host.is_empty() {
                            dash(ui);
                        } else {
                            text_cell(ui, &o.host).on_hover_text(&o.host);
                        }
                    });
                }
                row.col(|ui| {
                    text_cell(ui, &o.name).on_hover_text(&o.name);
                });
                if cols.kind {
                    row.col(|ui| {
                        cell_pad(ui);
                        ui.add(
                            wl_kit::egui::Label::new(
                                RichText::new(&o.content_type).color(Palette::muted()),
                            )
                            .truncate(),
                        );
                    });
                }
                row.col(|ui| {
                    if o.size > LARGE {
                        ui.style_mut().visuals.override_text_color =
                            Some(Severity::Warning.color());
                    }
                    num_cell(ui, &format::bytes(o.size));
                });
                if row.response().clicked() {
                    out.picked = Some(o.id);
                }
            });
        });
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn columns_always_fit_their_width() {
        for w in [430.0_f32, 520.0, 640.0, 760.0, 800.0, 1100.0] {
            let c = Cols::for_width(w);
            assert!(c.min_width() <= w, "{w}: needs {}", c.min_width());
            assert_eq!(
                c.heads().len(),
                2 + usize::from(c.packet) + usize::from(c.host) + usize::from(c.kind)
            );
        }
    }
}
