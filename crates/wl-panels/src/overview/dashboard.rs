//! Dashboard: responsive card grid with KPIs, throughput, protocols, talkers and services.

use wl_kit::charts::{
    TimeSelection, proportion_bar, protocol_ranked_bars, ranked_bars, throughput_chart_select,
};
use wl_kit::egui::{self, Rect, ScrollArea, Sense, Ui, UiBuilder, vec2};
use wl_kit::theme::{Mode, Palette, Theme, mode, spacing, theme};
use wl_kit::widgets::{empty_state, stat_card_h};
use wl_model::StatsSnapshot;

use super::actions::OverviewAction;
use super::cards::{card, content_height};
use super::dashboard_data::{Derived, derive};
use super::grid::{Card, place};
use super::window_scope::{WINDOW_ROW_H, WindowScope, window_row};

#[derive(Default)]
pub struct Dashboard {
    derived: Derived,
    /// Time window picked on the throughput chart (survives page changes).
    selection: Option<TimeSelection>,
    /// Scope of the Protocols / Talkers / Services cards and the window's statistics.
    window: WindowScope,
    key: Option<(u64, u64, usize, usize, Mode, Theme)>,
}

const WAITING: &str = "Computing window statistics\u{2026}";

fn muted_note(ui: &mut Ui, text: &str) {
    ui.label(egui::RichText::new(text).color(Palette::muted()));
}

impl Dashboard {
    fn refresh(&mut self, s: &StatsSnapshot) {
        let key = (
            s.total_packets,
            s.total_bytes,
            s.rate.len(),
            s.conversations.len(),
            mode(),
            theme(),
        );
        if self.key != Some(key) {
            self.derived = derive(s);
            self.key = Some(key);
        }
    }

    /// The time window picked on the throughput chart.
    pub fn selection(&self) -> Option<TimeSelection> {
        self.selection
    }

    pub fn set_selection(&mut self, s: Option<TimeSelection>) {
        self.selection = s;
    }

    /// Statistics of the packets in `[from, to]` seconds, computed by the app on request.
    pub fn set_window_stats(&mut self, from: u32, to: u32, s: &StatsSnapshot) {
        self.window.set_stats(from, to, s);
    }

    /// Shows the cards for the selected window instead of the whole capture (screenshots).
    pub fn show_window_scope(&mut self) {
        self.window.scope = super::window_scope::Scope::Window;
    }

    /// Drops window statistics (a new capture was opened).
    pub fn clear_window_stats(&mut self) {
        self.window.clear();
    }

    pub fn ui(&mut self, ui: &mut Ui, stats: &StatsSnapshot) -> Vec<OverviewAction> {
        if stats.total_packets == 0 {
            empty_state(
                ui,
                "~",
                "Nothing captured yet",
                "Start a live capture or open a pcap file to see an overview.",
            );
            return Vec::new();
        }
        self.refresh(stats);
        let mut actions = Vec::new();
        self.window.sync(self.selection.as_ref(), &mut actions);
        ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                let width = ui.available_width().max(200.0);
                let (placed, height) = place(width);
                let (area, _) = ui.allocate_exact_size(vec2(width, height), Sense::hover());
                for p in placed {
                    let rect = p.rect.translate(area.min.to_vec2());
                    self.draw(ui, p.card, rect, stats, &mut actions);
                }
            });
        actions
    }

    fn draw(
        &mut self,
        ui: &mut Ui,
        which: Card,
        rect: Rect,
        stats: &StatsSnapshot,
        actions: &mut Vec<OverviewAction>,
    ) {
        let sel = self.selection;
        let windowed = self.window.windowed(sel.as_ref());
        // Window data once computed; until then `waiting` replaces the cards' content.
        let ready = self.window.ready(sel.as_ref());
        let waiting = windowed && ready.is_none();
        let d = if windowed {
            ready.unwrap_or(&self.derived)
        } else {
            &self.derived
        };
        let suffix = if windowed {
            " \u{b7} selected window"
        } else {
            ""
        };
        match which {
            Card::Kpi(i) => {
                let k = &d.kpis[i];
                let mut cell = ui.new_child(UiBuilder::new().max_rect(rect));
                cell.set_clip_rect(rect.intersect(ui.clip_rect()));
                stat_card_h(
                    &mut cell,
                    k.title,
                    &k.value,
                    k.sub.as_deref(),
                    Some(rect.height()),
                );
            }
            Card::Throughput => {
                let (selection, scope) = (&mut self.selection, &mut self.window.scope);
                card(ui, rect, "Live throughput", |ui| {
                    window_row(ui, selection, scope, &stats.rate, actions);
                    let h = content_height(rect) - WINDOW_ROW_H - spacing::SM;
                    throughput_chart_select(ui, &stats.rate, h, selection);
                });
            }
            Card::Protocols => {
                card(ui, rect, &format!("Protocols{suffix}"), |ui| {
                    ui.spacing_mut().item_spacing.y = spacing::SM;
                    if waiting {
                        return muted_note(ui, WAITING);
                    }
                    proportion_bar(ui, &d.protocol_bar, 16.0);
                    protocol_ranked_bars(ui, &d.protocol_rows);
                });
            }
            Card::Talkers => {
                card(ui, rect, &format!("Top talkers{suffix}"), |ui| {
                    if waiting {
                        return muted_note(ui, WAITING);
                    }
                    ranked_bars(ui, &d.talkers, Palette::accent())
                });
            }
            Card::Services => {
                card(ui, rect, &format!("Top services & ports{suffix}"), |ui| {
                    if waiting {
                        muted_note(ui, WAITING);
                    } else if d.services.is_empty() {
                        muted_note(ui, "No port-based traffic yet.");
                    } else {
                        ranked_bars(ui, &d.services, Palette::ok());
                    }
                });
            }
        }
    }
}
