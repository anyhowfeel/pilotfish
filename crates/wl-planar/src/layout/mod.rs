//! The whole pipeline: a layout of a host graph with the fewest crossings it can reach.

mod component;
mod leaves;
mod pack;
mod peel;
mod reduce;
mod shape;

use std::time::{Duration, Instant};

use crate::crossing::count_crossings;
use crate::draw::{self, Relax};
use crate::embedding::Embedding;
use crate::geometry::Point;
use crate::graph::Graph;
use crate::{lr, planarize};
use component::{Drawn, Part, draw_component};

#[derive(Debug, Clone)]
pub struct Options {
    /// Importance per edge slot; heavier edges are kept crossing-free first. Empty means all equal.
    pub weight: Vec<f64>,
    /// Radius of each vertex's disc, so neighbours do not overlap. Empty means all `radius_default`.
    pub radius: Vec<f64>,
    pub radius_default: f64,
    /// Preferred distance between linked vertices.
    pub edge_len: f64,
    /// The pipeline stops improving when this much time has passed.
    pub budget: Duration,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            weight: Vec::new(),
            radius: Vec::new(),
            radius_default: 8.0,
            edge_len: 100.0,
            budget: Duration::from_millis(250),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Layout {
    pub pos: Vec<Point>,
    /// Crossing pairs of edges in `pos`.
    pub crossings: usize,
    /// The graph is planar, so `crossings` is 0.
    pub planar: bool,
}

/// The stages that need the planarity test and the planar drawing, behind one seam so the
/// composition can be tested with simple stand-ins.
pub(crate) struct Stages<'a> {
    pub embed: &'a dyn Fn(&Graph) -> Option<Embedding>,
    pub draw: &'a dyn Fn(&Graph, &Embedding) -> Vec<Point>,
    pub relax: &'a dyn Fn(&Graph, &mut [Point], &Relax),
    /// Edge slots to keep, given the slots most important first.
    pub planar_part: &'a dyn Fn(&Graph, &[usize]) -> Vec<bool>,
}

impl Stages<'static> {
    fn real() -> Self {
        Stages {
            embed: &lr::embed,
            draw: &draw::straight_line,
            relax: &draw::relax,
            planar_part: &planarize::maximal_planar,
        }
    }
}

pub fn layout(g: &Graph, opts: &Options) -> Layout {
    layout_with(g, opts, &Stages::real())
}

pub(crate) fn layout_with(g: &Graph, opts: &Options, stages: &Stages) -> Layout {
    let deadline = Instant::now() + opts.budget;
    let comps = g.components();
    let mut left: usize = comps.iter().map(Vec::len).sum();
    let mut drawn = Vec::with_capacity(comps.len());
    for comp in &comps {
        let part = Part::new(g, comp, opts);
        let share = deadline
            .saturating_duration_since(Instant::now())
            .mul_f64(comp.len() as f64 / left as f64);
        left -= comp.len();
        drawn.push(draw_component(&part, opts, Instant::now() + share, stages));
    }
    let planar = drawn.iter().all(|d| d.planar);
    let pos = assemble(g.vertex_count(), &comps, drawn, opts);
    let crossings = count_crossings(g, &pos);
    Layout {
        pos,
        crossings,
        planar,
    }
}

/// Packs the drawn components and writes their vertices at global positions.
fn assemble(n: usize, comps: &[Vec<usize>], drawn: Vec<Drawn>, opts: &Options) -> Vec<Point> {
    let margin = opts.edge_len / 2.0;
    let boxes: Vec<(Point, Point)> = drawn.iter().map(|d| bounds(&d.pos, &d.radius)).collect();
    let sizes: Vec<(f64, f64)> = boxes
        .iter()
        .map(|b| (b.1.x - b.0.x + margin, b.1.y - b.0.y + margin))
        .collect();
    let corners = pack::pack(&sizes);
    let mut pos = vec![Point::default(); n];
    for (((comp, d), b), c) in comps.iter().zip(&drawn).zip(&boxes).zip(&corners) {
        let shift = Point::new(c.x + margin / 2.0 - b.0.x, c.y + margin / 2.0 - b.0.y);
        for (&v, p) in comp.iter().zip(&d.pos) {
            pos[v] = Point::new(p.x + shift.x, p.y + shift.y);
        }
    }
    pos
}

/// Corners of the box around the discs of one drawing.
fn bounds(pos: &[Point], radius: &[f64]) -> (Point, Point) {
    let mut lo = Point::new(f64::MAX, f64::MAX);
    let mut hi = Point::new(f64::MIN, f64::MIN);
    for (p, r) in pos.iter().zip(radius) {
        lo = Point::new(lo.x.min(p.x - r), lo.y.min(p.y - r));
        hi = Point::new(hi.x.max(p.x + r), hi.y.max(p.y + r));
    }
    (lo, hi)
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
