//! DNS query log (one row per transaction): summary strip, filters, sortable table.
//! Data arrives from the app through `set_state`; "Show in Packets" leaves as an action.

mod cols;
#[cfg(test)]
mod layout_tests;
mod model;
mod summary;
mod table;

use std::sync::Arc;

use wl_kit::egui::{Key, RichText, Ui, vec2};
use wl_kit::theme::{Palette, spacing};
use wl_kit::widgets::{empty_state, pill_toggle};
use wl_model::DnsQuery;

use crate::overview::{SortState, filter_box};
use model::{CLASS_LABELS, DnsStats, Filter, SortCol, aggregate, build};

pub use model::{aggregate as stats, ms_text};

/// Page heights below this hide the summary strip and the top-names chips.
const COMPACT_H: f32 = 330.0;

/// What the panel asks the app to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsAction {
    /// The panel is visible and has no data: scan the capture.
    Load,
    /// Select this frame in Packets and switch to that page.
    ShowInPackets(u64),
}

#[derive(Debug, Clone, Default)]
pub enum DnsState {
    /// Nothing requested yet.
    #[default]
    Idle,
    Loading,
    Ready(Arc<Vec<DnsQuery>>),
    Error(String),
}

pub struct DnsPanel {
    state: DnsState,
    filter: Filter,
    sort: SortState<SortCol>,
    selected: Option<u64>,
    order: Vec<u32>,
    stats: DnsStats,
    dirty: bool,
    scroll_to: Option<usize>,
}

impl Default for DnsPanel {
    fn default() -> Self {
        Self {
            state: DnsState::Idle,
            filter: Filter::default(),
            sort: SortState::new(SortCol::Time, false),
            selected: None,
            order: Vec::new(),
            stats: DnsStats::default(),
            dirty: true,
            scroll_to: None,
        }
    }
}

impl DnsPanel {
    pub fn set_state(&mut self, state: DnsState) {
        if let DnsState::Ready(q) = &state {
            self.stats = aggregate(q);
        }
        self.state = state;
        self.dirty = true;
    }

    /// Forgets the data of the previous capture (the next visit reloads).
    pub fn invalidate(&mut self) {
        self.set_state(DnsState::Idle);
        self.selected = None;
    }

    pub fn state(&self) -> &DnsState {
        &self.state
    }

    /// Search text used by the table filter (screenshots / tests).
    pub fn set_query(&mut self, q: &str) {
        self.filter.query = q.to_owned();
        self.dirty = true;
    }

    fn rebuild(&mut self, all: &[DnsQuery]) {
        if self.dirty {
            self.order = build(all, &self.filter, self.sort);
            self.dirty = false;
        }
    }

    fn keyboard(&mut self, ui: &Ui, all: &[DnsQuery], out: &mut Vec<DnsAction>) {
        if ui.memory(|m| m.focused().is_some()) || self.order.is_empty() {
            return;
        }
        let cur = self
            .selected
            .and_then(|f| self.order.iter().position(|&i| all[i as usize].frame == f));
        let (down, up, enter) = ui.input(|i| {
            (
                i.key_pressed(Key::ArrowDown),
                i.key_pressed(Key::ArrowUp),
                i.key_pressed(Key::Enter),
            )
        });
        let last = self.order.len() - 1;
        let pick = if down {
            Some(cur.map_or(0, |c| (c + 1).min(last)))
        } else if up {
            Some(cur.map_or(0, |c| c.saturating_sub(1)))
        } else {
            None
        };
        if let Some(i) = pick {
            self.selected = Some(all[self.order[i] as usize].frame);
            self.scroll_to = Some(i);
        } else if enter && let Some(f) = self.selected {
            out.push(DnsAction::ShowInPackets(f));
        }
    }

    pub fn ui(&mut self, ui: &mut Ui) -> Vec<DnsAction> {
        let mut out = Vec::new();
        let all = match self.state.clone() {
            DnsState::Idle => {
                out.push(DnsAction::Load);
                empty_state(
                    ui,
                    "...",
                    "Reading DNS traffic",
                    "Scanning the capture for DNS queries.",
                );
                return out;
            }
            DnsState::Loading => {
                empty_state(
                    ui,
                    "...",
                    "Reading DNS traffic",
                    "Scanning the capture for DNS queries.",
                );
                return out;
            }
            DnsState::Error(e) => {
                empty_state(ui, "!", "Could not read DNS traffic", &e);
                return out;
            }
            DnsState::Ready(q) => q,
        };
        if all.is_empty() {
            empty_state(
                ui,
                "dns",
                "No DNS traffic",
                "Queries and responses on port 53 appear here. Use Decode As for other ports.",
            );
            return out;
        }
        // Short pages give the room to the table: the summary comes back with more height.
        if ui.available_height() >= COMPACT_H {
            summary::strip(ui, &self.stats);
            ui.add_space(spacing::SM);
            if summary::top_names(ui, &self.stats, &mut self.filter.query) {
                self.dirty = true;
            }
            ui.add_space(spacing::SM);
        }
        self.toolbar(ui, all.len());
        ui.add_space(spacing::SM);
        self.rebuild(&all);
        self.keyboard(ui, &all, &mut out);
        let t = table::TableIn {
            all: &all,
            rows: &self.order,
            sort: self.sort,
            selected: self.selected,
            scroll_to: self.scroll_to.take(),
        };
        let res = table::table(ui, &t);
        if let Some(c) = res.sort {
            self.sort.toggle(c);
            self.dirty = true;
        }
        if let Some(i) = res.picked {
            let frame = all[self.order[i] as usize].frame;
            self.selected = Some(frame);
            out.push(DnsAction::ShowInPackets(frame));
        }
        out
    }

    fn toolbar(&mut self, ui: &mut Ui, total: usize) {
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing = vec2(spacing::SM, spacing::SM);
            let mut changed = filter_box(
                ui,
                &mut self.filter.query,
                "Name, client, answer\u{2026}",
                260.0,
            );
            for (i, label) in CLASS_LABELS.iter().enumerate() {
                changed |= pill_toggle(ui, &mut self.filter.classes[i], label).changed();
            }
            ui.label(
                RichText::new(format!("{} of {total}", self.order.len()))
                    .small()
                    .color(Palette::muted()),
            );
            self.dirty |= changed;
        });
    }
}
