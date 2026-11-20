//! "Flows" page: pick one conversation (or 2..N hosts) and read it as a sequence diagram
//! (Wireshark's Flow Graph) or as TCP stream graphs (time-sequence, throughput, RTT, window).

mod actions;
mod geom;
mod graph;
mod grip;
mod header;
mod lanes;
mod list;
mod marks;
mod paint;
mod parts;
mod tabs;
mod tcp_series;
mod tcp_view;
mod virt;

#[cfg(test)]
mod layout_tests;

pub use actions::{FlowsAction, FlowsData};
pub use tabs::Tab;

use wl_kit::egui::{Align, Frame, Layout, Margin, ScrollArea, Stroke, Ui, vec2};
use wl_kit::theme::{Palette, RADIUS, spacing};
use wl_kit::widgets::{empty_state, segmented_w};
use wl_model::{FlowEvents, FlowSel, TcpSamples};

use graph::FlowGraph;
use header::Header;
use list::List;
use parts::{legend, loading_or_error, summary, tcp_capable, tcp_summary};
use tcp_view::TcpView;

/// Width of the conversation list; narrower windows get the smaller one.
const LIST_W: f32 = 300.0;
const LIST_W_NARROW: f32 = 252.0;
const LIST_W_TINY: f32 = 188.0;
/// Narrowest the list can be dragged to.
const LIST_MIN_W: f32 = 160.0;
const NARROW_BELOW: f32 = 900.0;
const TINY_BELOW: f32 = 600.0;
/// Below this width of the right pane the tabs use their short labels.
const SHORT_TABS_BELOW: f32 = 480.0;

#[derive(Default)]
pub struct FlowsPanel {
    sel: Option<FlowSel>,
    tab: Tab,
    list: List,
    graph: FlowGraph,
    tcp: TcpView,
    asked_flow: bool,
    asked_tcp: bool,
    /// Width the user dragged the list to (None = the responsive default).
    list_w: Option<f32>,
}

impl FlowsPanel {
    /// Shows this conversation (called by the list, context menus and the CLI).
    pub fn open(&mut self, sel: FlowSel) {
        if self.sel.as_ref() == Some(&sel) {
            return;
        }
        self.sel = Some(sel);
        self.asked_flow = false;
        self.asked_tcp = false;
        self.graph.reset();
        self.tcp.reset();
    }

    pub fn selection(&self) -> Option<&FlowSel> {
        self.sel.as_ref()
    }

    pub fn set_tab(&mut self, tab: Tab) {
        self.tab = tab;
    }

    /// Pre-selects a frame of the flow graph (screenshots).
    pub fn select_frame(&mut self, frame: u64) {
        self.graph.select_frame(frame);
    }

    /// Forces both data passes to run again (live captures grew, user pressed reload).
    pub fn reload(&mut self) {
        self.asked_flow = false;
        self.asked_tcp = false;
    }

    pub fn ui(&mut self, ui: &mut Ui, d: &FlowsData) -> Vec<FlowsAction> {
        let mut out = Vec::new();
        let avail = ui.available_width();
        let default_w = match avail {
            w if w < TINY_BELOW => LIST_W_TINY,
            w if w < NARROW_BELOW => LIST_W_NARROW,
            _ => LIST_W,
        };
        let list_w = self
            .list_w
            .unwrap_or(default_w)
            .clamp(LIST_MIN_W, (avail * 0.6).max(LIST_MIN_W));
        let h = ui.available_height();
        let mut chosen = None;
        ui.horizontal_top(|ui| {
            ui.spacing_mut().item_spacing.x = spacing::LG;
            let list_box =
                ui.allocate_ui_with_layout(vec2(list_w, h), Layout::top_down(Align::Min), |ui| {
                    Frame::new()
                        .fill(Palette::surface())
                        .stroke(Stroke::new(1.0, Palette::border()))
                        .corner_radius(RADIUS)
                        .inner_margin(Margin::same(spacing::SM as i8))
                        .show(ui, |ui| {
                            ui.set_min_size(vec2(
                                list_w - 2.0 * spacing::SM - 2.0,
                                h - 2.0 * spacing::SM - 2.0,
                            ));
                            ui.set_max_width(list_w - 2.0 * spacing::SM - 2.0);
                            chosen = self.list.ui(ui, d.stats, self.sel.as_ref());
                        });
                });
            if let Some(w) = grip::list_grip(ui, list_box.response.rect, list_w, avail, LIST_MIN_W)
            {
                self.list_w = Some(w);
            }
            ui.allocate_ui_with_layout(
                vec2(ui.available_width(), h),
                Layout::top_down(Align::Min),
                |ui| self.detail(ui, d, &mut out),
            );
        });
        if let Some(sel) = chosen {
            self.open(sel);
        }
        out
    }

    fn detail(&mut self, ui: &mut Ui, d: &FlowsData, out: &mut Vec<FlowsAction>) {
        let Some(sel) = self.sel.clone() else {
            empty_state(
                ui,
                "~",
                "Pick a conversation",
                "Choose a conversation on the left to see its packets as a flow graph or TCP stream graphs.",
            );
            return;
        };
        let flow = d.flow.filter(|(s, _)| **s == sel).map(|(_, e)| e);
        let tcp = d.tcp.filter(|(s, _)| **s == sel).map(|(_, t)| t);
        self.header(ui, &sel, (flow, tcp), out);
        ui.add_space(spacing::SM);
        let tcp_ok = tcp_capable(&sel);
        if !tcp_ok {
            self.tab = Tab::Flow;
        }
        let short = ui.available_width() < SHORT_TABS_BELOW;
        let tabs: Vec<(Tab, &str)> = Tab::ALL
            .into_iter()
            .filter(|t| tcp_ok || !t.is_tcp())
            .map(|t| (t, if short { t.short() } else { t.label() }))
            .collect();
        let w = ui.available_width().min(120.0 * tabs.len() as f32);
        let mut tab = self.tab;
        ui.push_id("flow_tabs", |ui| segmented_w(ui, &mut tab, &tabs, w));
        self.tab = tab;
        ui.add_space(spacing::SM);
        if self.tab.is_tcp() {
            self.tcp_body(ui, d, &sel, out);
        } else {
            self.flow_body(ui, d, &sel, flow, out);
        }
    }

    fn flow_body(
        &mut self,
        ui: &mut Ui,
        d: &FlowsData,
        sel: &FlowSel,
        flow: Option<&FlowEvents>,
        out: &mut Vec<FlowsAction>,
    ) {
        if !self.asked_flow {
            self.asked_flow = true;
            out.push(FlowsAction::LoadFlow(sel.clone()));
        }
        let Some(ev) = flow else {
            loading_or_error(ui, d.flow_error, "Reading packets");
            return;
        };
        if ev.events.is_empty() {
            empty_state(ui, "~", "No packets", "Nothing matched this selection.");
            return;
        }
        legend(ui, self.graph.counts());
        self.graph.ui(ui, ev, d.rev, out);
    }

    fn tcp_body(&mut self, ui: &mut Ui, d: &FlowsData, sel: &FlowSel, out: &mut Vec<FlowsAction>) {
        if !self.asked_tcp {
            self.asked_tcp = true;
            out.push(FlowsAction::LoadTcp(sel.clone()));
        }
        match d.tcp.filter(|(s, _)| **s == *sel) {
            Some((_, samples)) => {
                let id = format!("tcp-{}", sel.title());
                let (tab, rev, page_h) = (self.tab, d.rev, ui.available_height());
                ScrollArea::vertical()
                    .id_salt("tcp_scroll")
                    .auto_shrink([false, false])
                    .show(ui, |ui| self.tcp.ui(ui, tab, samples, rev, &id, page_h));
            }
            None => loading_or_error(ui, d.tcp_error, "Reading TCP segments"),
        }
    }

    fn header(
        &mut self,
        ui: &mut Ui,
        sel: &FlowSel,
        (flow, tcp): (Option<&FlowEvents>, Option<&TcpSamples>),
        out: &mut Vec<FlowsAction>,
    ) {
        let summary = match (flow, tcp) {
            (Some(e), _) => summary(e, self.graph.lanes().hosts.len()),
            (None, Some(t)) => tcp_summary(t),
            _ => String::new(),
        };
        let h = Header {
            sel,
            frame: self
                .graph
                .selected_frame(flow.unwrap_or(&FlowEvents::default())),
            summary: &summary,
            truncated: flow.is_some_and(|e| e.truncated),
        };
        if header::show(ui, &h, out).reload {
            self.reload();
        }
    }
}
