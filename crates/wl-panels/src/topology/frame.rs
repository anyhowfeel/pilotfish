//! One frame of the canvas: relax the layout, project to screen, handle input, paint.

use std::time::Duration;

use wl_kit::egui::{
    self, Align2, CornerRadius, FontId, Rect, Response, Sense, Stroke, StrokeKind, Ui, pos2,
};
use wl_kit::theme::{Palette, RADIUS, spacing};
use wl_kit::widgets::text::elided_galley;

use super::declutter::{self, Candidate};
use super::state::Resolved;
use super::viewport::{Viewport, bounds};
use super::{TopologyView, controls, hit, paint, search, tooltip};

/// Canvas minus the bands covered by the overlays (`insets` = top, bottom heights), keeping
/// at least half of the height so tiny windows still get a usable graph area.
pub(super) fn clear_area(rect: Rect, insets: (f32, f32)) -> Rect {
    // Keep at least 40 % of the height for the graph; the bands are only compressed beyond that.
    let spare = rect.height() * 0.6;
    let (top, bottom) = insets;
    let k = ((top + bottom + 2.0 * spacing::SM) / spare.max(1.0)).max(1.0);
    Rect::from_min_max(
        pos2(rect.left(), rect.top() + (top + spacing::SM) / k),
        pos2(
            rect.right(),
            rect.bottom() - (bottom.max(0.0) + spacing::SM) / k,
        ),
    )
}

/// Layout relaxation budget per frame.
const BUDGET: Duration = Duration::from_micros(1000);
const FIT_PAD: f32 = 44.0;
const LABEL_MAX_W: f32 = 150.0;
/// Canvases shorter than this (or with a floating inspector) fold the option rows away.
const COMPACT_H: f32 = 480.0;
/// Narrower canvases do not fit the three-way layout switch beside the search field.
const COMPACT_W: f32 = 440.0;
const MAX_CANDIDATES: usize = 120;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Drag {
    Node(usize),
    Pan,
}

impl TopologyView {
    pub(super) fn canvas(
        &mut self,
        ui: &mut Ui,
        rect: Rect,
        sel: Resolved,
        floating_card: Option<Rect>,
    ) {
        let resp = ui.allocate_rect(rect, Sense::click_and_drag());
        let ctx = ui.ctx().clone();
        let radius = CornerRadius::same(RADIUS);
        ui.painter().rect_filled(rect, radius, Palette::panel());
        let painter = ui.painter_at(rect);
        let mut busy = self.layout.step(BUDGET);
        let target = bounds(self.layout.pos.iter().copied(), 34.0)
            .map(|b| Viewport::fit(b, clear_area(rect, self.insets), FIT_PAD));
        if let (true, Some(t)) = (self.auto_fit, target) {
            if self.vp.distance(&t) > 0.5 {
                self.vp.ease_to(&t, 0.25);
                busy = true;
            } else {
                self.vp = t;
            }
        }
        self.project(rect);
        let hover = self.hover(&resp, rect);
        self.input(ui, &resp, rect, hover);
        tooltip::show(&resp, &self.graph, hover, &*self.resolver);
        search::matches(&self.graph, &self.search, &mut self.buf.matches);
        self.place_labels(&painter, sel, hover);
        let animate = self.live && ctx.global_style().animation_time > 0.0;
        let scene = paint::Scene {
            g: &self.graph,
            rect,
            zoom: self.vp.zoom,
            sel,
            hover,
            directions: self.opts.directions,
            encrypted: self.opts.encrypted,
            pinned: &self.layout.pinned,
            time: ui.input(|i| i.time),
            animate,
        };
        paint::links(&painter, &scene, &self.buf);
        paint::nodes(&painter, &scene, &self.buf);
        paint::labels(&painter, &scene, &self.buf);
        if self.graph.nodes.is_empty() {
            painter.text(
                rect.center(),
                Align2::CENTER_CENTER,
                "No links match the current filters",
                FontId::proportional(14.0),
                Palette::muted(),
            );
        }
        ui.painter().rect_stroke(
            rect,
            radius,
            Stroke::new(1.0, Palette::border()),
            StrokeKind::Inside,
        );
        let compact =
            floating_card.is_some() || rect.height() < COMPACT_H || rect.width() < COMPACT_W;
        let cmd = controls::controls(
            &ctx,
            rect,
            &mut self.opts,
            &mut self.search,
            compact,
            &mut self.opts_open,
        );
        let (w, h) = (rect.width(), rect.height());
        let kind = if floating_card.is_some() || w < 360.0 {
            controls::LegendKind::Hidden
        } else if h >= 470.0 && w >= 460.0 {
            controls::LegendKind::Full
        } else {
            controls::LegendKind::Compact
        };
        let legend = controls::legend(&ctx, rect, &self.graph, kind);
        let mut bottom = rect.bottom() - legend.top().min(rect.bottom());
        if let Some(card) = floating_card {
            bottom = bottom.max(rect.bottom() - card.top());
        } else {
            let counts = controls::counts(&ctx, rect, &self.graph, self.layout.readout());
            bottom = bottom.max(rect.bottom() - counts.top());
        }
        self.insets = (cmd.rect.map_or(0.0, |r| r.bottom() - rect.top()), bottom);
        self.apply(cmd, rect);
        if busy {
            ctx.request_repaint();
        } else if animate && !self.graph.links.is_empty() {
            ctx.request_repaint_after(Duration::from_millis(33));
        }
    }

    /// World -> screen for nodes, plus the hit-test geometry (reused buffers).
    fn project(&mut self, rect: Rect) {
        let b = &mut self.buf;
        b.screen.clear();
        b.discs.clear();
        b.segs.clear();
        for (n, p) in self.graph.nodes.iter().zip(&self.layout.pos) {
            let s = self.vp.to_screen(rect, *p);
            b.screen.push(s);
            b.discs
                .push((s, (n.radius * self.vp.zoom.clamp(0.5, 2.5)).max(3.5)));
        }
        for l in &self.graph.links {
            let w = paint::half_width(l.t, self.vp.zoom);
            b.segs.push((b.screen[l.a], b.screen[l.b], w));
        }
    }

    fn hover(&self, resp: &Response, _rect: Rect) -> Resolved {
        let Some(p) = resp.hover_pos() else {
            return Resolved::None;
        };
        if let Some(i) = hit::node_at(&self.buf.discs, p, 3.0) {
            return Resolved::Node(i);
        }
        hit::edge_at(&self.buf.segs, p, 4.0).map_or(Resolved::None, Resolved::Link)
    }

    /// Chooses which labels to draw: forced (selected / hovered / search hits) first, then by rank.
    fn place_labels(&mut self, painter: &egui::Painter, sel: Resolved, hover: Resolved) {
        let ppp = painter.ctx().pixels_per_point();
        let mode = wl_kit::theme::mode();
        if (self.buf.galley_ppp - ppp).abs() > f32::EPSILON || self.buf.galley_mode != Some(mode) {
            self.buf.galley_ppp = ppp;
            self.buf.galley_mode = Some(mode);
            self.buf.galleys.iter_mut().for_each(|g| *g = None);
        }
        let mut order: Vec<(usize, bool)> = Vec::new();
        for r in [sel, hover] {
            if let Resolved::Node(i) = r {
                order.push((i, true));
            }
        }
        order.extend(self.buf.matches.iter().map(|&i| (i, true)));
        if self.opts.labels {
            order.extend((0..self.graph.nodes.len().min(MAX_CANDIDATES)).map(|i| (i, false)));
        }
        self.buf.cands.clear();
        let font = FontId::proportional(11.5);
        for (i, forced) in order {
            let Some(slot) = self.buf.galleys.get_mut(i) else {
                continue;
            };
            let g = slot.get_or_insert_with(|| {
                elided_galley(
                    painter,
                    self.graph.nodes[i].label(),
                    font.clone(),
                    egui::Color32::PLACEHOLDER,
                    LABEL_MAX_W,
                )
            });
            let (c, r) = self.buf.discs[i];
            self.buf.cands.push(Candidate {
                node: i,
                center: c,
                radius: r,
                w: g.size().x,
                h: g.size().y,
                forced,
            });
        }
        let max = (8.0 + 16.0 * self.vp.zoom).clamp(8.0, 90.0) as usize;
        declutter::place(&self.buf.cands, &self.buf.discs, max, &mut self.buf.labels);
    }
}
