//! Hosts table: sortable, filterable, click selects a display filter.

use std::sync::Arc;

use wl_kit::egui::{self, ScrollArea, Ui, vec2};
use wl_kit::format;
use wl_kit::table::{HEADER_H, TableCols, cell_pad, num_cell, text_cell};
use wl_kit::theme::{Palette, row_h, spacing};
use wl_kit::widgets::{PillStyle, centered_row, empty_state, pill};
use wl_model::StatsSnapshot;

use super::actions::OverviewAction;
use super::hosts_sort::{HostCol, host_filter, total_bytes, visible};
use super::resolver::{NameResolver, NoNames};
use super::sort::SortState;
use super::table_cells::{filter_box, share_bar, sort_header};

const MIN_TABLE_W: f32 = 700.0;
const SCOPE_PILL_W: f32 = 68.0;

pub struct HostsPanel {
    filter: String,
    sort: SortState<HostCol>,
    resolver: Box<dyn NameResolver>,
    selected: Option<Arc<str>>,
    key: Option<(u64, u64, usize)>,
    key_filter: String,
    key_sort: SortState<HostCol>,
    rows: Vec<usize>,
    max_total: u64,
}

impl Default for HostsPanel {
    fn default() -> Self {
        Self {
            filter: String::new(),
            sort: SortState::new(HostCol::Total, true),
            resolver: Box::new(NoNames),
            selected: None,
            key: None,
            key_filter: String::new(),
            key_sort: SortState::new(HostCol::Total, true),
            rows: Vec::new(),
            max_total: 0,
        }
    }
}

impl HostsPanel {
    pub fn set_resolver(&mut self, r: Box<dyn NameResolver>) {
        self.resolver = r;
        self.invalidate();
    }

    /// Force the filtered/sorted view to be recomputed (e.g. when new names arrived).
    pub fn invalidate(&mut self) {
        self.key = None;
    }

    fn refresh(&mut self, s: &StatsSnapshot) {
        let key = (s.total_packets, s.total_bytes, s.hosts.len());
        if self.key == Some(key) && self.key_filter == self.filter && self.key_sort == self.sort {
            return;
        }
        self.key_filter.clone_from(&self.filter);
        self.key_sort = self.sort;
        let r = &self.resolver;
        self.rows = visible(&s.hosts, &self.filter, self.sort, &|a| r.name(a));
        self.max_total = s.hosts.iter().map(total_bytes).max().unwrap_or(0);
        self.key = Some(key);
    }

    pub fn ui(&mut self, ui: &mut Ui, stats: &StatsSnapshot) -> Vec<OverviewAction> {
        let mut out = Vec::new();
        if stats.hosts.is_empty() {
            empty_state(
                ui,
                "#",
                "No hosts yet",
                "Start a capture or open a file to see who is talking.",
            );
            return out;
        }
        self.refresh(stats);
        centered_row(ui, 30.0, |ui| {
            if filter_box(
                ui,
                &mut self.filter,
                "Filter by address or name\u{2026}",
                260.0,
            ) {
                self.invalidate();
            }
            ui.label(
                egui::RichText::new(format!("{} / {} hosts", self.rows.len(), stats.hosts.len()))
                    .color(Palette::muted()),
            );
        });
        ui.add_space(spacing::SM);
        let mut clicked_sort = None;
        let rows = &self.rows;
        let hosts = &stats.hosts;
        let (sort, max, resolver) = (self.sort, self.max_total, &self.resolver);
        let mut picked = None;
        let selected = self.selected.clone();
        let avail_w = ui.available_width();
        let avail_h = ui.available_height().max(HEADER_H + row_h());
        let table_w = avail_w.max(MIN_TABLE_W);
        ui.style_mut().interaction.selectable_labels = false;
        ScrollArea::horizontal()
            .id_salt("hosts_hscroll")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.allocate_ui(vec2(table_w, avail_h), |ui| {
                    TableCols::new()
                        .flex(150.0)
                        .fixed(90.0)
                        .num(74.0)
                        .num(74.0)
                        .num(88.0)
                        .num(88.0)
                        .fixed(116.0)
                        .build(ui)
                        .auto_shrink([false, false])
                        .max_scroll_height((avail_h - HEADER_H).max(row_h()))
                        .header(HEADER_H, |mut h| {
                            let heads = [
                                ("Address", HostCol::Address, false),
                                ("Scope", HostCol::Scope, false),
                                ("Pkts in", HostCol::PacketsIn, true),
                                ("Pkts out", HostCol::PacketsOut, true),
                                ("Bytes in", HostCol::BytesIn, true),
                                ("Bytes out", HostCol::BytesOut, true),
                                ("Share", HostCol::Total, false),
                            ];
                            for (t, c, right) in heads {
                                h.col(|ui| {
                                    if sort_header(ui, t, c, &sort, right) {
                                        clicked_sort = Some(c);
                                    }
                                });
                            }
                        })
                        .body(|body| {
                            body.rows(row_h(), rows.len(), |mut row| {
                                let host = &hosts[rows[row.index()]];
                                row.set_selected(selected.as_deref() == Some(&*host.addr));
                                row.col(|ui| {
                                    let r = match resolver.name(&host.addr) {
                                        Some(n) => text_cell(ui, &format!("{}  {n}", host.addr)),
                                        None => text_cell(ui, &host.addr),
                                    };
                                    r.on_hover_text(&*host.addr);
                                });
                                row.col(|ui| {
                                    cell_pad(ui);
                                    let t = if host.is_private { "private" } else { "public" };
                                    let c = Palette::scope(host.is_private);
                                    pill(ui, t, c, PillStyle::column(SCOPE_PILL_W));
                                });
                                row.col(|ui| num_cell(ui, &format::count(host.packets_in)));
                                row.col(|ui| num_cell(ui, &format::count(host.packets_out)));
                                row.col(|ui| num_cell(ui, &format::bytes(host.bytes_in)));
                                row.col(|ui| num_cell(ui, &format::bytes(host.bytes_out)));
                                row.col(|ui| {
                                    share_bar(
                                        ui,
                                        if max > 0 {
                                            total_bytes(host) as f32 / max as f32
                                        } else {
                                            0.0
                                        },
                                    )
                                });
                                if row.response().clicked() {
                                    picked = Some(host.addr.clone());
                                }
                            });
                        });
                });
            });
        if let Some(c) = clicked_sort {
            self.sort.toggle(c);
        }
        if let Some(a) = picked {
            out.push(OverviewAction::ApplyFilter(host_filter(&a)));
            self.selected = Some(a);
        }
        out
    }
}
