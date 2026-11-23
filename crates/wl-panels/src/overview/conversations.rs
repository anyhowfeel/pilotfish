//! Conversations table: A:port <-> B:port with service, protocol, volume and duration.

use wl_kit::egui::{self, CursorIcon, ScrollArea, Ui, vec2};
use wl_kit::format;
use wl_kit::table::{HEADER_H, TableCols, cell_pad, num_cell, text_cell};
use wl_kit::theme::{Palette, row_h, spacing};
use wl_kit::widgets::{PROTOCOL_COL_W, PROTOCOL_PILL_W, centered_row, empty_state, protocol_pill};
use wl_model::{FlowKey, StatsSnapshot};

use super::actions::OverviewAction;
use super::conversations_sort::{FlowCol, duration, flow_filter, service, visible};
use super::endpoint_cell::endpoints_cell;
use super::resolver::{NameResolver, NoNames, StreamLookup};
use super::sort::SortState;
use super::table_cells::{filter_box, sort_header};

const MIN_TABLE_W: f32 = 720.0;
const PROCESS_HEAD: &str = "Process";

pub struct ConversationsPanel {
    filter: String,
    sort: SortState<FlowCol>,
    streams: Option<StreamLookup>,
    resolver: Box<dyn NameResolver>,
    selected: Option<FlowKey>,
    key: Option<(u64, u64, usize)>,
    key_filter: String,
    key_sort: SortState<FlowCol>,
    rows: Vec<usize>,
}

impl Default for ConversationsPanel {
    fn default() -> Self {
        Self {
            filter: String::new(),
            sort: SortState::new(FlowCol::Bytes, true),
            streams: None,
            resolver: Box::new(NoNames),
            selected: None,
            key: None,
            key_filter: String::new(),
            key_sort: SortState::new(FlowCol::Bytes, true),
            rows: Vec::new(),
        }
    }
}

impl ConversationsPanel {
    /// Inject the flow -> stream index lookup; without it no "Follow" button is shown.
    pub fn set_stream_lookup(&mut self, l: StreamLookup) {
        self.streams = Some(l);
    }

    pub fn set_resolver(&mut self, r: Box<dyn NameResolver>) {
        self.resolver = r;
    }

    fn refresh(&mut self, s: &StatsSnapshot) {
        let key = (s.total_packets, s.total_bytes, s.conversations.len());
        if self.key == Some(key) && self.key_filter == self.filter && self.key_sort == self.sort {
            return;
        }
        self.key_filter.clone_from(&self.filter);
        self.key_sort = self.sort;
        self.rows = visible(&s.conversations, &self.filter, self.sort);
        self.key = Some(key);
    }

    pub fn ui(&mut self, ui: &mut Ui, stats: &StatsSnapshot) -> Vec<OverviewAction> {
        let mut out = Vec::new();
        if stats.conversations.is_empty() {
            empty_state(
                ui,
                "=",
                "No conversations yet",
                "Start a capture or open a file to see conversations.",
            );
            return out;
        }
        self.refresh(stats);
        centered_row(ui, 30.0, |ui| {
            if filter_box(
                ui,
                &mut self.filter,
                "Filter by address, port, protocol\u{2026}",
                280.0,
            ) {
                self.key = None;
            }
            let n = format!(
                "{} / {} conversations",
                self.rows.len(),
                stats.conversations.len()
            );
            ui.label(egui::RichText::new(n).color(Palette::muted()));
        });
        ui.add_space(spacing::SM);
        let (sort, rows, convs) = (self.sort, &self.rows, &stats.conversations);
        let (streams, selected) = (&self.streams, self.selected.clone());
        let (resolver, procs) = (&self.resolver, self.resolver.has_processes());
        let (mut clicked_sort, mut picked, mut follow) = (None, None, None);
        let mut flow = None;
        let avail_h = ui.available_height().max(HEADER_H + row_h());
        let table_w = ui.available_width().max(MIN_TABLE_W);
        ui.style_mut().interaction.selectable_labels = false;
        ScrollArea::horizontal()
            .id_salt("convs_hscroll")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.allocate_ui(vec2(table_w, avail_h), |ui| {
                    let mut cols = TableCols::new().flex(190.0).fixed(88.0);
                    if procs {
                        cols = cols.flex(120.0);
                    }
                    cols.fixed(PROTOCOL_COL_W)
                        .num(72.0)
                        .num(86.0)
                        .num(78.0)
                        .fixed(72.0)
                        .build(ui)
                        .auto_shrink([false, false])
                        .max_scroll_height((avail_h - HEADER_H).max(row_h()))
                        .header(HEADER_H, |mut h| {
                            let heads = [
                                ("Endpoints", Some(FlowCol::Endpoints), false),
                                ("Service", Some(FlowCol::Service), false),
                                (PROCESS_HEAD, None, false),
                                ("Protocol", Some(FlowCol::Protocol), false),
                                ("Packets", Some(FlowCol::Packets), true),
                                ("Bytes", Some(FlowCol::Bytes), true),
                                ("Duration", Some(FlowCol::Duration), true),
                                ("", None, false),
                            ];
                            for (t, c, right) in heads {
                                if t == PROCESS_HEAD && !procs {
                                    continue;
                                }
                                h.col(|ui| match c {
                                    Some(c) => {
                                        if sort_header(ui, t, c, &sort, right) {
                                            clicked_sort = Some(c);
                                        }
                                    }
                                    None => {
                                        ui.label(
                                            egui::RichText::new(t)
                                                .small()
                                                .strong()
                                                .color(Palette::muted()),
                                        );
                                    }
                                });
                            }
                        })
                        .body(|body| {
                            body.rows(row_h(), rows.len(), |mut row| {
                                let c = &convs[rows[row.index()]];
                                row.set_selected(selected.as_ref() == Some(&c.key));
                                row.col(|ui| {
                                    endpoints_cell(ui, c);
                                });
                                row.col(|ui| match service(c) {
                                    Some(s) => {
                                        text_cell(ui, s);
                                    }
                                    None => {
                                        cell_pad(ui);
                                        ui.add(
                                            egui::Label::new(
                                                egui::RichText::new("\u{2014}")
                                                    .color(Palette::muted()),
                                            )
                                            .selectable(false),
                                        );
                                    }
                                });
                                if procs {
                                    row.col(|ui| {
                                        let p = resolver.flow_process(&c.key);
                                        text_cell(ui, &p.map(|p| p.label()).unwrap_or_default());
                                    });
                                }
                                row.col(|ui| {
                                    cell_pad(ui);
                                    protocol_pill(ui, &c.protocol, PROTOCOL_PILL_W);
                                });
                                row.col(|ui| num_cell(ui, &format::count(c.packets)));
                                row.col(|ui| num_cell(ui, &format::bytes(c.bytes)));
                                row.col(|ui| num_cell(ui, &format::duration(duration(c))));
                                row.col(|ui| {
                                    if let Some(s) = streams.as_ref().and_then(|f| f(&c.key))
                                        && ui
                                            .small_button("Follow")
                                            .on_hover_cursor(CursorIcon::PointingHand)
                                            .on_hover_text("Filter packets in this stream")
                                            .clicked()
                                    {
                                        follow = Some(s);
                                    }
                                });
                                let resp = row.response();
                                if resp.clicked() {
                                    picked = Some(c.key.clone());
                                }
                                resp.context_menu(|ui| {
                                    if ui.button("Open in Flow graph").clicked() {
                                        flow = Some(c.key.clone());
                                        ui.close();
                                    }
                                });
                            });
                        });
                });
            });
        if let Some(c) = clicked_sort {
            self.sort.toggle(c);
        }
        if let Some(k) = flow {
            out.push(OverviewAction::OpenFlow(wl_model::FlowSel::Conversation(k)));
        } else if let Some(s) = follow {
            out.push(OverviewAction::Follow(s));
        } else if let Some(k) = picked {
            if let Some(c) = stats.conversations.iter().find(|c| c.key == k) {
                out.push(OverviewAction::ApplyFilter(flow_filter(c)));
            }
            self.selected = Some(k);
        }
        out
    }
}
