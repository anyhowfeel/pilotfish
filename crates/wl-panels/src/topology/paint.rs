//! Painter-level drawing of links, nodes and labels (all colours from theme tokens).

use wl_kit::egui::{Color32, CornerRadius, Painter, Pos2, Rect, Shape, Stroke, pos2, vec2};
use wl_kit::theme::{Palette, protocol_color, tint};
use wl_kit::widgets::paint_lock;

use super::model::Graph;
use super::scale::{edge_alpha, edge_width};
use super::state::{Buffers, Resolved};

/// Links animated at most (the heaviest ones), to keep the paint loop cheap.
const MAX_FLOWING: usize = 40;
const DIM: f32 = 0.16;
const NODE_DIM: f32 = 0.32;

pub struct Scene<'a> {
    pub g: &'a Graph,
    pub rect: Rect,
    pub zoom: f32,
    pub sel: Resolved,
    pub hover: Resolved,
    pub directions: bool,
    pub encrypted: bool,
    pub pinned: &'a [bool],
    /// Seconds, drives the flow dashes when `animate`.
    pub time: f64,
    pub animate: bool,
}

fn mul_alpha(a: u8, k: f32) -> u8 {
    (f32::from(a) * k).round() as u8
}

/// Sender -> receiver of the dominant direction and its share of the bytes.
pub fn dominant(g: &Graph, link: usize) -> (usize, usize, f32) {
    let l = &g.links[link];
    let fwd = l.a_to_b as f32 / l.bytes.max(1) as f32;
    if fwd >= 0.5 {
        (l.a, l.b, fwd)
    } else {
        (l.b, l.a, 1.0 - fwd)
    }
}

/// Half of the on-screen stroke width of a link (hit-test tolerance).
pub fn half_width(t: f32, zoom: f32) -> f32 {
    edge_width(t) * zoom.clamp(0.7, 1.5) / 2.0
}

pub fn links(p: &Painter, s: &Scene, buf: &Buffers) {
    let mut flowing = 0;
    let focus = s.sel != Resolved::None;
    for (i, l) in s.g.links.iter().enumerate() {
        let (a, b) = (buf.screen[l.a], buf.screen[l.b]);
        if a == b || !s.rect.expand(40.0).intersects(Rect::from_two_pos(a, b)) {
            continue;
        }
        let lit = s.sel.touches_link(s.g, i);
        let hot = s.hover == Resolved::Link(i) || s.sel == Resolved::Link(i);
        let secure = s.encrypted && l.encrypted;
        // "Encrypted" mode: everything that is not encrypted fades out.
        let k = if (focus && !lit) || (s.encrypted && !secure) {
            DIM
        } else {
            1.0
        };
        let alpha = if hot {
            255
        } else {
            mul_alpha(edge_alpha(l.t), k)
        };
        let color = tint(protocol_color(&l.protocol), alpha);
        let w = half_width(l.t, s.zoom) * 2.0 + if hot { 1.5 } else { 0.0 };
        p.line_segment([a, b], Stroke::new(w, color));
        if secure && k == 1.0 {
            // Lock at the middle of the link, on a disc that keeps it readable over the line.
            let m = a + (b - a) * 0.5;
            p.circle_filled(m, 8.5, Palette::panel());
            paint_lock(p, m, 11.0, color);
        }
        let (from, to, share) = dominant(s.g, i);
        let (pf, pt) = (buf.screen[from], buf.screen[to]);
        if s.directions && share >= 0.62 && k == 1.0 {
            arrow(p, pf, pt, w, color);
        }
        if s.animate && flowing < MAX_FLOWING && l.t >= 0.35 && k == 1.0 {
            flowing += 1;
            let ink = tint(Palette::text(), 90);
            let off = (s.time * 26.0) as f32;
            p.extend(Shape::dashed_line_with_offset(
                &[pf, pt],
                Stroke::new(w * 0.7, ink),
                &[5.0],
                &[11.0],
                off,
            ));
        }
    }
}

fn arrow(p: &Painter, from: Pos2, to: Pos2, w: f32, color: Color32) {
    let d = (to - from).normalized();
    if !d.x.is_finite() {
        return;
    }
    let n = vec2(-d.y, d.x);
    let m = from + (to - from) * 0.58;
    let sz = 4.5 + w;
    let pts = vec![
        m + d * sz,
        m - d * sz * 0.6 + n * sz * 0.6,
        m - d * sz * 0.6 - n * sz * 0.6,
    ];
    p.add(Shape::convex_polygon(pts, color, Stroke::NONE));
}

pub fn nodes(p: &Painter, s: &Scene, buf: &Buffers) {
    for (i, n) in s.g.nodes.iter().enumerate() {
        let (c, r) = buf.discs[i];
        if !s.rect.expand(r + 8.0).contains(c) {
            continue;
        }
        let k = if s.sel.touches_node(s.g, i) {
            1.0
        } else {
            NODE_DIM
        };
        let base = Palette::scope(n.private);
        p.circle_filled(c, r + 1.5, Palette::panel());
        p.circle_filled(c, r, base.gamma_multiply(k));
        if n.hub && k == 1.0 {
            p.circle_stroke(c, r + 4.0, Stroke::new(1.5, tint(Palette::accent(), 120)));
        }
        if s.pinned.get(i).copied().unwrap_or(false) {
            p.circle_filled(c, (r * 0.28).max(1.5), Palette::panel());
        }
        let picked = s.sel == Resolved::Node(i);
        if picked || s.hover == Resolved::Node(i) {
            let ring = if picked {
                Palette::text()
            } else {
                tint(Palette::text(), 150)
            };
            p.circle_stroke(c, r + 3.0, Stroke::new(2.0, ring));
        } else if buf.matches.contains(&i) {
            p.circle_stroke(c, r + 3.0, Stroke::new(2.0, Palette::accent()));
        }
    }
}

pub fn labels(p: &Painter, s: &Scene, buf: &Buffers) {
    for (i, rect) in &buf.labels {
        let Some(g) = buf.galleys.get(*i).and_then(|g| g.as_ref()) else {
            continue;
        };
        let dim = !s.sel.touches_node(s.g, *i);
        let pill = rect.expand2(vec2(3.0, 1.0));
        let bg = if dim { 60 } else { 205 };
        p.rect_filled(pill, CornerRadius::same(4), tint(Palette::panel(), bg));
        let ink = if dim {
            Palette::muted()
        } else {
            Palette::text()
        };
        p.galley(
            pos2(rect.left(), rect.center().y - g.size().y / 2.0),
            g.clone(),
            ink,
        );
    }
}
