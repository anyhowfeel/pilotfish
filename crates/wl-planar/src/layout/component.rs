//! One connected component through the stages: peel, draw the core, put the leaves back.

use std::time::Instant;

use super::leaves::{self, Fit};
use super::peel::peel;
use super::reduce::reduce;
use super::shape::{circle, is_finite, scale_edges, separate_discs};
use super::{Options, Stages};
use crate::draw::Relax;
use crate::geometry::Point;
use crate::graph::Graph;

/// Gap kept between vertex discs.
const DISC_GAP: f64 = 2.0;

/// A component drawn in its own coordinates.
pub(super) struct Drawn {
    pub pos: Vec<Point>,
    pub radius: Vec<f64>,
    pub planar: bool,
}

/// A component renumbered `0..n`, with the options that belong to its vertices and edge slots.
pub(super) struct Part {
    pub g: Graph,
    pub weight: Vec<f64>,
    pub radius: Vec<f64>,
}

impl Part {
    pub fn new(g: &Graph, comp: &[usize], opts: &Options) -> Self {
        let (sub, origin) = g.induced(comp);
        Part {
            g: sub,
            weight: origin
                .iter()
                .map(|&e| opts.weight.get(e).copied().unwrap_or(1.0))
                .collect(),
            radius: comp
                .iter()
                .map(|&v| opts.radius.get(v).copied().unwrap_or(opts.radius_default))
                .collect(),
        }
    }
}

pub(super) fn draw_component(part: &Part, opts: &Options, deadline: Instant, st: &Stages) -> Drawn {
    let g = &part.g;
    let peeled = peel(g);
    let ids: Vec<usize> = (0..g.vertex_count()).filter(|&v| peeled.core[v]).collect();
    let mut pos = vec![Point::default(); g.vertex_count()];
    let mut planar = true;
    if !ids.is_empty() {
        let (core, origin) = g.induced(&ids);
        let weight: Vec<f64> = origin.iter().map(|&e| part.weight[e]).collect();
        let radius: Vec<f64> = ids.iter().map(|&v| part.radius[v]).collect();
        let (placed, ok) = draw_core(&core, &weight, &radius, opts, deadline, st);
        planar = ok;
        for (&v, p) in ids.iter().zip(placed) {
            pos[v] = p;
        }
    }
    let fit = Fit {
        radius: &part.radius,
        edge_len: opts.edge_len,
    };
    leaves::attach(g, &peeled, &mut pos, &fit);
    separate_discs(&mut pos, &part.radius, DISC_GAP);
    Drawn {
        pos,
        radius: part.radius.clone(),
        planar,
    }
}

/// A planar core is drawn as it is; otherwise its largest planar part is drawn first and the other
/// edges are added to that drawing, which is then polished and has its crossings reduced.
fn draw_core(
    core: &Graph,
    weight: &[f64],
    radius: &[f64],
    opts: &Options,
    deadline: Instant,
    st: &Stages,
) -> (Vec<Point>, bool) {
    let relax = Relax {
        deadline: Some(deadline),
        ideal_len: opts.edge_len,
        ..Relax::default()
    };
    if let Some(e) = (st.embed)(core) {
        let mut pos = sound((st.draw)(core, &e), core, opts);
        scale_edges(core, &mut pos, opts.edge_len);
        (st.relax)(core, &mut pos, &relax);
        return (pos, true);
    }
    let keep = (st.planar_part)(core, &priority(core, weight));
    let part = core.with_edges(&keep);
    let drawn = (st.embed)(&part).map_or_else(Vec::new, |e| (st.draw)(&part, &e));
    let mut pos = sound(drawn, core, opts);
    scale_edges(core, &mut pos, opts.edge_len);
    (st.relax)(core, &mut pos, &relax);
    reduce(core, &mut pos, weight, radius, Some(deadline));
    (pos, false)
}

/// Heaviest edge first, ties by slot.
fn priority(g: &Graph, weight: &[f64]) -> Vec<usize> {
    let mut slots: Vec<usize> = g.valid_edges().collect();
    slots.sort_by(|&a, &b| weight[b].total_cmp(&weight[a]).then(a.cmp(&b)));
    slots
}

/// A drawing of the right size with finite coordinates, or a circle when a stage let us down.
fn sound(pos: Vec<Point>, g: &Graph, opts: &Options) -> Vec<Point> {
    if pos.len() == g.vertex_count() && is_finite(&pos) {
        pos
    } else {
        circle(g.vertex_count(), opts.edge_len)
    }
}
