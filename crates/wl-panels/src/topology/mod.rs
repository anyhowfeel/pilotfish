//! Network topology map: hosts as nodes, host pairs as links whose width/opacity follow the bytes.
//! Layout by `fjadra` (d3-force port, Barnes-Hut); all painting is done here with the egui painter.

mod card;
mod controls;
mod declutter;
pub mod demo;
mod filters;
mod frame;
mod hit;
mod interact;
mod layout;
mod model;
mod paint;
mod radial;
mod scale;
mod search;
mod state;
mod tooltip;
mod viewport;

#[cfg(test)]
mod interaction_tests;
#[cfg(test)]
mod layout_tests;

use wl_kit::egui::{Rect, Ui, pos2, vec2};
use wl_kit::theme::spacing;
use wl_kit::widgets::empty_state;
use wl_model::StatsSnapshot;

use crate::overview::{NameResolver, NoNames, OverviewAction};
use layout::Layout;
use model::{Filters, Graph};
use state::{Buffers, Options, Resolved, Selection};
use viewport::Viewport;

type Key = (u64, u64, usize, usize, Filters);

pub struct TopologyView {
    graph: Graph,
    key: Option<Key>,
    layout: Layout,
    vp: Viewport,
    auto_fit: bool,
    opts: Options,
    search: String,
    sel: Selection,
    resolver: Box<dyn NameResolver>,
    live: bool,
    drag: Option<frame::Drag>,
    buf: Buffers,
    last_focus: Option<usize>,
    /// Heights covered by the overlays at the top / bottom of the canvas (measured last frame).
    insets: (f32, f32),
    opts_open: bool,
}

impl Default for TopologyView {
    fn default() -> Self {
        Self {
            graph: Graph::default(),
            key: None,
            layout: Layout::default(),
            vp: Viewport::default(),
            auto_fit: true,
            opts: Options::default(),
            search: String::new(),
            sel: Selection::None,
            resolver: Box::new(NoNames),
            live: false,
            drag: None,
            buf: Buffers::default(),
            last_focus: None,
            insets: (0.0, 0.0),
            opts_open: false,
        }
    }
}

impl TopologyView {
    pub fn set_resolver(&mut self, r: Box<dyn NameResolver>) {
        self.resolver = r;
        self.invalidate();
    }

    /// Force the graph to be rebuilt (e.g. when new host names arrived).
    pub fn invalidate(&mut self) {
        self.key = None;
    }

    /// Selects a host programmatically (opens the inspector); unknown hosts are ignored on resolve.
    pub fn select_host(&mut self, addr: &str) {
        self.sel = Selection::Node(addr.into());
    }

    /// Screenshot helper: comma list of `radial`, `directions`, `nolabels`.
    pub fn apply_spec(&mut self, spec: &str) {
        for w in spec.split(',').map(str::trim) {
            match w {
                "radial" => self.opts.mode = layout::Mode::Radial,
                "directions" => self.opts.directions = true,
                "encrypted" => self.opts.encrypted = true,
                "nolabels" => self.opts.labels = false,
                _ => {}
            }
        }
    }

    /// Live captures animate the traffic flow on the heaviest links (unless motion is reduced).
    pub fn set_live(&mut self, live: bool) {
        self.live = live;
    }

    fn refresh(&mut self, s: &StatsSnapshot) {
        let key = (
            s.total_packets,
            s.total_bytes,
            s.edges.len(),
            s.hosts.len(),
            self.opts.filters,
        );
        if self.key == Some(key) {
            return;
        }
        self.key = Some(key);
        let r = &self.resolver;
        self.graph = Graph::build(s, &self.opts.filters, &|a| r.name(a));
        self.buf.galleys.clear();
        self.buf.galleys.resize(self.graph.nodes.len(), None);
        let focus = self.focus();
        self.layout.set_mode(self.opts.mode, &self.graph, focus);
        self.last_focus = focus;
    }

    fn focus(&self) -> Option<usize> {
        match self.sel.resolve(&self.graph) {
            Resolved::Node(i) => Some(i),
            _ => None,
        }
    }

    pub fn ui(&mut self, ui: &mut Ui, snap: &StatsSnapshot) -> Vec<OverviewAction> {
        let mut out = Vec::new();
        if snap.hosts.len() < 2 || snap.edges.is_empty() {
            let (title, hint) = if snap.total_packets == 0 {
                (
                    "No hosts yet",
                    "Start a capture or open a file to see who talks to whom.",
                )
            } else {
                (
                    "Not enough hosts",
                    "The map needs at least two hosts exchanging traffic.",
                )
            };
            empty_state(ui, "o", title, hint);
            return out;
        }
        self.refresh(snap);
        let full = ui.available_rect_before_wrap();
        let sel = self.sel.resolve(&self.graph);
        let (canvas, card) = split(full, sel != Resolved::None);
        self.canvas(ui, canvas, sel, card.filter(|c| c.floating).map(|c| c.rect));
        if let Some(c) = card
            && card::show(ui, c.rect, &self.graph, sel, &mut out)
        {
            self.sel = Selection::None;
        }
        out
    }
}

/// Windows narrower than this show the inspector as a floating card instead of docking it.
const DOCK_MIN_W: f32 = 700.0;

#[derive(Clone, Copy)]
struct CardPlace {
    rect: Rect,
    /// Drawn over the canvas (narrow windows) instead of beside it.
    floating: bool,
}

/// Canvas rect and (when something is selected) the inspector placement.
fn split(full: Rect, with_card: bool) -> (Rect, Option<CardPlace>) {
    if !with_card {
        return (full, None);
    }
    let m = spacing::MD;
    if full.width() < DOCK_MIN_W {
        let h = (full.height() * 0.45).min(260.0);
        let rect = Rect::from_min_max(
            pos2(full.left() + m, full.bottom() - h - m),
            full.right_bottom() - vec2(m, m),
        );
        return (
            full,
            Some(CardPlace {
                rect,
                floating: true,
            }),
        );
    }
    let card = Rect::from_min_max(
        full.right_top() - vec2(card::CARD_W, 0.0),
        full.right_bottom(),
    );
    let canvas = Rect::from_min_max(full.min, card.left_bottom() - vec2(spacing::SM, 0.0));
    (
        canvas,
        Some(CardPlace {
            rect: card,
            floating: false,
        }),
    )
}
