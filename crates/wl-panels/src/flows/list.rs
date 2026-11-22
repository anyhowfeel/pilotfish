//! Left pane: pick the conversation (or 2..N hosts) to draw. Virtualised painted rows.

use std::sync::Arc;

use wl_kit::egui::{ScrollArea, Ui};
use wl_kit::format;
use wl_kit::text::contains_ci;
use wl_kit::theme::{Palette, protocol_color, spacing};
use wl_kit::widgets::{empty_state, segmented_w};
use wl_model::{FlowSel, HostStat, StatsSnapshot};

use super::list_row::{Cell, Lead, ROW, Row, item};
use crate::overview::conversations_sort::{FlowCol, duration, endpoint_parts, visible};
use crate::overview::{NameResolver, SortState};

const MAX_HOSTS: usize = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Mode {
    #[default]
    Conversations,
    Hosts,
}

#[derive(Default)]
pub struct List {
    mode: Mode,
    filter: String,
    picked: Vec<Arc<str>>,
    key: Option<(u64, usize, String, Mode)>,
    rows: Vec<usize>,
    resolver: Option<Box<dyn NameResolver>>,
}

fn share(bytes: u64, top: u64) -> f32 {
    if top == 0 {
        0.0
    } else {
        bytes as f32 / top as f32
    }
}

/// Hosts ordered by traffic, filtered by substring.
pub fn host_rows(hosts: &[HostStat], needle: &str) -> Vec<usize> {
    let n = needle.to_lowercase();
    let mut idx: Vec<usize> = (0..hosts.len())
        .filter(|&i| n.is_empty() || contains_ci(&hosts[i].addr, &n))
        .collect();
    let bytes = |i: usize| hosts[i].bytes_in + hosts[i].bytes_out;
    idx.sort_by(|&a, &b| bytes(b).cmp(&bytes(a)).then(a.cmp(&b)));
    idx
}

impl List {
    pub fn set_resolver(&mut self, r: Box<dyn NameResolver>) {
        self.resolver = Some(r);
    }

    /// Full-width filter field; Escape clears it.
    fn filter_field(&mut self, ui: &mut Ui, w: f32) {
        let edit = ui.add(
            wl_kit::widgets::text_field(&mut self.filter)
                .hint_text("Filter\u{2026}")
                .desired_width(w),
        );
        if edit.has_focus() && ui.input(|i| i.key_pressed(wl_kit::egui::Key::Escape)) {
            self.filter.clear();
        }
    }

    fn refresh(&mut self, s: &StatsSnapshot) {
        let key = (
            s.total_packets,
            s.conversations.len() + s.hosts.len(),
            self.filter.clone(),
            self.mode,
        );
        if self.key.as_ref() == Some(&key) {
            return;
        }
        self.rows = match self.mode {
            Mode::Conversations => visible(
                &s.conversations,
                &self.filter,
                SortState::new(FlowCol::Bytes, true),
            ),
            Mode::Hosts => host_rows(&s.hosts, &self.filter),
        };
        self.key = Some(key);
    }

    /// Draws the pane; returns a newly chosen selection.
    pub fn ui(
        &mut self,
        ui: &mut Ui,
        s: &StatsSnapshot,
        current: Option<&FlowSel>,
    ) -> Option<FlowSel> {
        let mut mode = self.mode;
        let w = ui.available_width();
        let modes = [
            (Mode::Conversations, "Conversations"),
            (Mode::Hosts, "Hosts"),
        ];
        ui.push_id("flow_mode", |ui| segmented_w(ui, &mut mode, &modes, w));
        self.mode = mode;
        ui.add_space(spacing::SM);
        self.filter_field(ui, w);
        ui.add_space(spacing::SM);
        self.refresh(s);
        if self.rows.is_empty() {
            let (title, hint) = match self.mode {
                Mode::Conversations => ("No conversations", "Flows appear once packets arrive."),
                Mode::Hosts => ("No hosts", "Hosts appear once packets arrive."),
            };
            empty_state(ui, "=", title, hint);
            return None;
        }
        if self.mode == Mode::Hosts {
            let hint = format!("Tick 2 to {MAX_HOSTS} hosts ({} ticked)", self.picked.len());
            ui.label(
                wl_kit::egui::RichText::new(hint)
                    .small()
                    .color(Palette::muted()),
            );
        }
        ScrollArea::vertical()
            .id_salt("flow_list")
            .auto_shrink([false, false])
            .show_rows(ui, ROW, self.rows.len(), |ui, range| {
                self.rows(ui, s, current, range)
            })
            .inner
    }

    fn rows(
        &mut self,
        ui: &mut Ui,
        s: &StatsSnapshot,
        current: Option<&FlowSel>,
        range: std::ops::Range<usize>,
    ) -> Option<FlowSel> {
        let mut chosen = None;
        let top = self.rows.first().map_or(0, |&i| match self.mode {
            Mode::Conversations => s.conversations[i].bytes,
            Mode::Hosts => s.hosts[i].bytes_in + s.hosts[i].bytes_out,
        });
        for r in range {
            let idx = self.rows[r];
            if self.mode == Mode::Conversations {
                let c = &s.conversations[idx];
                let sel = FlowSel::Conversation(c.key.clone());
                let who = self.resolver.as_ref().and_then(|r| r.flow_process(&c.key));
                let mut title = endpoint_parts(c);
                if let Some(p) = who {
                    title.push((format!("  {}", p.name), true));
                }
                let cells = [
                    Cell::new(format!("{} pkts", format::count(c.packets)), 64.0, 2),
                    Cell::new(format::bytes(c.bytes), 68.0, 0),
                    Cell::new(format::duration(duration(c)), 56.0, 1),
                ];
                let row = Row {
                    selected: current == Some(&sel),
                    title: &title,
                    lead: Lead::Protocol(&c.protocol, protocol_color(&c.protocol)),
                    cells: &cells,
                    share: share(c.bytes, top),
                };
                if item(ui, &row) {
                    chosen = Some(sel);
                }
            } else {
                chosen = chosen.or(self.host_row(ui, &s.hosts[idx], top));
            }
        }
        chosen
    }

    fn host_row(&mut self, ui: &mut Ui, h: &HostStat, top: u64) -> Option<FlowSel> {
        let on = self.picked.contains(&h.addr);
        let dot = if on {
            Palette::accent()
        } else {
            Palette::muted()
        };
        let cells = [
            Cell::new(format!("{} in", format::bytes(h.bytes_in)), 88.0, 0),
            Cell::new(format!("{} out", format::bytes(h.bytes_out)), 96.0, 1),
        ];
        let title = [(h.addr.to_string(), false)];
        let row = Row {
            selected: on,
            title: &title,
            lead: Lead::Dot(dot),
            cells: &cells,
            share: share(h.bytes_in + h.bytes_out, top),
        };
        if !item(ui, &row) {
            return None;
        }
        if on {
            self.picked.retain(|a| *a != h.addr);
        } else if self.picked.len() < MAX_HOSTS {
            self.picked.push(h.addr.clone());
        }
        (self.picked.len() >= 2).then(|| FlowSel::Hosts(self.picked.clone()))
    }
}
