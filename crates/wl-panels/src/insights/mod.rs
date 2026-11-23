//! "Network health" page: header + summary strip pinned on top, scrollable grouped findings.
mod actions;
mod category;
mod finding_card;
mod header;
#[cfg(test)]
mod layout_tests;
mod logic;
mod rules;
mod secondary;
mod state;

pub use actions::InsightsAction;
pub use category::Category;
pub use logic::{HealthState, View, findings, group, health_state, view};
pub use rules::{InsightRules, MuteChoice, Thresholds, mute_choices};

use wl_kit::egui::{self, Align, Key, Layout, Rect, RichText, ScrollArea, Ui, vec2};
use wl_kit::theme::{Palette, spacing};
use wl_kit::widgets::{chip, empty_state, segmented_w};
use wl_model::{Analyses, ExpertSeverity, InsightSeverity, StatsSnapshot, Wireshark};

use crate::dns::{DnsAction, DnsPanel};
use crate::features::{InsightContext, synthesize_insights};
use crate::needs::needs_wireshark;
use finding_card::finding_card;
use header::{Summary, header, summary_strip};

/// Content column never grows wider than this (centred on large windows).
const MAX_W: f32 = 1100.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Tab {
    #[default]
    Findings,
    Expert,
    Hierarchy,
    Dns,
}

#[derive(Default)]
pub struct InsightsPanel {
    tab: Tab,
    severity_filter: Option<ExpertSeverity>,
    dns: DnsPanel,
    /// Keyboard-selected finding (None until the user presses Up/Down).
    selected: Option<usize>,
}

impl InsightsPanel {
    /// The DNS tab (the app feeds it with `set_state` / `invalidate`).
    pub fn dns_mut(&mut self) -> &mut DnsPanel {
        &mut self.dns
    }

    /// Shows the DNS tab (screenshots).
    pub fn show_dns(&mut self) {
        self.tab = Tab::Dns;
    }

    pub fn ui(
        &mut self,
        ui: &mut Ui,
        stats: &StatsSnapshot,
        analyses: &Analyses,
        cx: &InsightContext,
    ) -> Vec<InsightsAction> {
        let mut actions = Vec::new();
        let all = synthesize_insights(
            analyses.expert.ready(),
            analyses.hierarchy.ready(),
            analyses.behavior.ready(),
            stats,
            cx,
        );
        let found = findings(&all);
        let total = stats.total_packets;
        if view(cx.wireshark, total, found.len(), analyses) == View::NeedsWireshark {
            centered(ui, |ui| needs_wireshark(ui, "Network health"));
            return actions;
        }
        centered(ui, |ui| {
            header(ui, &mut actions);
            ui.add_space(spacing::MD);
            let tabs = [
                (Tab::Findings, "Findings"),
                (Tab::Expert, "Expert info"),
                (Tab::Hierarchy, "Protocol hierarchy"),
                (Tab::Dns, "DNS"),
            ];
            let w = ui.available_width().min(560.0);
            segmented_w(ui, &mut self.tab, &tabs, w);
            ui.add_space(spacing::MD);
            if self.tab == Tab::Findings && total > 0 {
                let (label, severity) = logic::strip(health_state(&found), analyses);
                let sum = Summary {
                    label,
                    severity,
                    critical: logic::count(&found, InsightSeverity::Critical),
                    warning: logic::count(&found, InsightSeverity::Warning),
                    info: logic::count(&found, InsightSeverity::Info),
                    packets: total,
                };
                summary_strip(ui, &sum);
                ui.add_space(spacing::MD);
            }
            if self.tab == Tab::Dns {
                // The DNS table scrolls on its own and fills the rest of the page.
                for a in self.dns.ui(ui) {
                    actions.push(match a {
                        DnsAction::Load => InsightsAction::LoadDns,
                        DnsAction::ShowInPackets(f) => InsightsAction::ShowInPackets(f),
                    });
                }
                return;
            }
            ScrollArea::vertical()
                .id_salt("wl_insights_scroll")
                .auto_shrink([false, false])
                .show(ui, |ui| match self.tab {
                    Tab::Findings => {
                        let shown = (total, cx.wireshark, analyses);
                        self.findings_ui(ui, &found, shown, &mut actions)
                    }
                    Tab::Expert => secondary::expert_view(
                        ui,
                        &mut self.severity_filter,
                        &analyses.expert,
                        &mut actions,
                    ),
                    Tab::Hierarchy => secondary::phs_view(ui, &analyses.hierarchy, &mut actions),
                    Tab::Dns => {}
                });
        });
        actions
    }

    fn findings_ui(
        &mut self,
        ui: &mut Ui,
        found: &[&wl_model::HealthInsight],
        (total, wireshark, analyses): (u64, Wireshark, &Analyses),
        actions: &mut Vec<InsightsAction>,
    ) {
        match view(wireshark, total, found.len(), analyses) {
            View::NoCapture => {
                empty_state(
                    ui,
                    "i",
                    "No capture loaded",
                    "Open a pcapng file or start a capture to see network health findings.",
                );
                return;
            }
            View::AllClear => {
                empty_state(
                    ui,
                    "ok",
                    "Nothing looks wrong",
                    "No retransmissions, resets, DNS failures or malformed frames were found.",
                );
                return;
            }
            View::NotRun => {
                empty_state(
                    ui,
                    "i",
                    "Analysis has not run",
                    "Use Re-analyse to check this capture.",
                );
                return;
            }
            View::Analysing => {
                empty_state(
                    ui,
                    "i",
                    "Analysing the capture",
                    "Findings appear when the analysis finishes.",
                );
                return;
            }
            View::Failed => {
                empty_state(ui, "!", "Analysis failed", &logic::failure_text(analyses));
                return;
            }
            View::NeedsWireshark => return,
            View::Findings => {}
        }
        if !analyses.failures().is_empty() {
            ui.label(RichText::new(logic::failure_text(analyses)).color(Palette::warn()));
            ui.add_space(spacing::SM);
        }
        self.keyboard(ui, found, actions);
        let mut idx = 0;
        for (cat, items) in group(found) {
            let id = ui.make_persistent_id(("wl_insights_group", cat.label()));
            egui::collapsing_header::CollapsingState::load_with_default_open(ui.ctx(), id, true)
                .show_header(ui, |ui| {
                    ui.label(
                        RichText::new(cat.label())
                            .strong()
                            .size(15.0)
                            .color(Palette::text()),
                    );
                    chip(ui, &items.len().to_string(), true);
                })
                .body_unindented(|ui| {
                    ui.spacing_mut().item_spacing.y = spacing::SM;
                    ui.add_space(spacing::XS);
                    for f in items {
                        let sel = self.selected == Some(idx);
                        let r = finding_card(ui, f, cat, sel, actions);
                        if sel
                            && ui.input(|i| {
                                i.key_pressed(Key::ArrowDown) || i.key_pressed(Key::ArrowUp)
                            })
                        {
                            ui.scroll_to_rect(r.expand(spacing::SM), None);
                        }
                        idx += 1;
                    }
                });
            ui.add_space(spacing::SM);
        }
    }

    /// Up/Down move the selection, Enter inspects it.
    fn keyboard(
        &mut self,
        ui: &Ui,
        found: &[&wl_model::HealthInsight],
        actions: &mut Vec<InsightsAction>,
    ) {
        let n = found.len();
        self.selected = self.selected.map(|s| s.min(n - 1));
        if ui.memory(|m| m.focused().is_some()) {
            return;
        }
        let order: Vec<&wl_model::HealthInsight> =
            group(found).into_iter().flat_map(|(_, v)| v).collect();
        ui.input(|i| {
            if i.key_pressed(Key::ArrowDown) {
                self.selected = Some(self.selected.map_or(0, |s| (s + 1).min(n - 1)));
            }
            if i.key_pressed(Key::ArrowUp) {
                self.selected = Some(self.selected.map_or(0, |s| s.saturating_sub(1)));
            }
            if i.key_pressed(Key::Enter)
                && let Some(f) = self
                    .selected
                    .and_then(|s| order.get(s))
                    .and_then(|f| f.suggested_filter.clone())
            {
                actions.push(InsightsAction::ApplyFilter(f));
            }
        });
    }
}

/// Runs `add` in a column at most `MAX_W` wide, horizontally centred in the available width.
fn centered(ui: &mut Ui, add: impl FnOnce(&mut Ui)) {
    let avail = ui.available_rect_before_wrap();
    let w = avail.width().min(MAX_W);
    let x = avail.left() + (avail.width() - w) / 2.0;
    let rect = Rect::from_min_size(egui::pos2(x, avail.top()), vec2(w, avail.height()));
    let mut col = ui.new_child(
        egui::UiBuilder::new()
            .max_rect(rect)
            .layout(Layout::top_down(Align::Min)),
    );
    add(&mut col);
    ui.allocate_rect(col.min_rect().union(avail), egui::Sense::hover());
}
