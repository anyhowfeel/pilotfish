//! Crossing reduction for drawings that still cross: a local search that moves one vertex at a
//! time and keeps a move only when the crossings of its edges get strictly fewer, or equally many
//! and lighter. Crossings never go up, and a vertex never lands on another vertex or edge.

use std::f64::consts::TAU;
use std::time::Instant;

use super::shape::crosses;
use crate::geometry::Point;
use crate::graph::Graph;

const MAX_PASSES: usize = 40;
/// Neighbours whose pairwise midpoints are tried; keeps hubs cheap.
const PAIR_NEIGHBOURS: usize = 8;
const DIRECTIONS: usize = 8;
const GAP: f64 = 2.0;

struct Search<'a> {
    g: &'a Graph,
    /// Valid edges as `(a, b, slot)`.
    edges: Vec<(usize, usize, usize)>,
    /// Importance per slot, scaled to at most one.
    weight: Vec<f64>,
    radius: &'a [f64],
}

/// `weight` and `radius` may be shorter than the graph; missing entries count as one and zero.
pub fn reduce(
    g: &Graph,
    pos: &mut [Point],
    weight: &[f64],
    radius: &[f64],
    deadline: Option<Instant>,
) {
    let top = weight.iter().copied().fold(0.0, f64::max);
    let radius: Vec<f64> = (0..g.vertex_count())
        .map(|v| radius.get(v).copied().unwrap_or(0.0))
        .collect();
    let s = Search {
        g,
        edges: g
            .valid_edges()
            .map(|e| (g.endpoints(e).0, g.endpoints(e).1, e))
            .collect(),
        weight: (0..g.edge_slots())
            .map(|e| match weight.get(e) {
                Some(w) if top > 0.0 => w / top,
                _ => 1.0,
            })
            .collect(),
        radius: &radius,
    };
    let late = || deadline.is_some_and(|d| Instant::now() >= d);
    for _ in 0..MAX_PASSES {
        let mut worst: Vec<(usize, usize)> = (0..g.vertex_count())
            .map(|v| (s.cost(pos, v).0, v))
            .filter(|c| c.0 > 0)
            .collect();
        worst.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
        let mut improved = false;
        for (_, v) in worst {
            if late() {
                return;
            }
            improved |= s.improve(pos, v);
        }
        if !improved {
            return;
        }
    }
}

fn better(a: (usize, f64), b: (usize, f64)) -> bool {
    a.0 < b.0 || (a.0 == b.0 && a.1 < b.1 - 1e-12)
}

fn seg_dist(p: Point, a: Point, b: Point) -> f64 {
    let (dx, dy) = (b.x - a.x, b.y - a.y);
    let len2 = dx * dx + dy * dy;
    let t = if len2 > 0.0 {
        (((p.x - a.x) * dx + (p.y - a.y) * dy) / len2).clamp(0.0, 1.0)
    } else {
        0.0
    };
    p.dist(Point::new(a.x + t * dx, a.y + t * dy))
}

impl Search<'_> {
    /// Crossings of the edges at `v` with every other edge, and their summed weights.
    fn cost(&self, pos: &[Point], v: usize) -> (usize, f64) {
        let (mut n, mut w) = (0, 0.0);
        for &e in self.g.incident(v) {
            let (a, b) = self.g.endpoints(e);
            let (x0, x1) = (pos[a].x.min(pos[b].x), pos[a].x.max(pos[b].x));
            let (y0, y1) = (pos[a].y.min(pos[b].y), pos[a].y.max(pos[b].y));
            for &(c, d, f) in &self.edges {
                if f == e {
                    continue;
                }
                let (p, q) = (pos[c], pos[d]);
                if p.x.max(q.x) < x0 - 1e-9 || p.x.min(q.x) > x1 + 1e-9 {
                    continue;
                }
                if p.y.max(q.y) < y0 - 1e-9 || p.y.min(q.y) > y1 + 1e-9 {
                    continue;
                }
                if crosses(pos, (a, b), (c, d)) {
                    n += 1;
                    w += self.weight[e] + self.weight[f];
                }
            }
        }
        (n, w)
    }

    fn candidates(&self, pos: &[Point], v: usize) -> Vec<Point> {
        let near: Vec<Point> = self.g.neighbors(v).iter().map(|&u| pos[u]).collect();
        let mut out = Vec::new();
        if near.is_empty() {
            return out;
        }
        let k = near.len() as f64;
        out.push(Point::new(
            near.iter().map(|p| p.x).sum::<f64>() / k,
            near.iter().map(|p| p.y).sum::<f64>() / k,
        ));
        let few = &near[..near.len().min(PAIR_NEIGHBOURS)];
        for (i, p) in few.iter().enumerate() {
            for q in &few[i + 1..] {
                out.push(Point::new((p.x + q.x) / 2.0, (p.y + q.y) / 2.0));
            }
        }
        let mean = near.iter().map(|p| p.dist(pos[v])).sum::<f64>() / k;
        for scale in [0.5, 0.2] {
            for d in 0..DIRECTIONS {
                let a = TAU * d as f64 / DIRECTIONS as f64;
                out.push(Point::new(
                    pos[v].x + mean * scale * a.cos(),
                    pos[v].y + mean * scale * a.sin(),
                ));
            }
        }
        out
    }

    fn free(&self, pos: &[Point], v: usize, p: Point) -> bool {
        let r = self.radius[v];
        let clear_of_vertices = (0..pos.len())
            .filter(|&w| w != v)
            .all(|w| p.dist(pos[w]) >= r + self.radius[w] + GAP);
        clear_of_vertices
            && self
                .edges
                .iter()
                .filter(|&&(a, b, _)| a != v && b != v)
                .all(|&(a, b, _)| seg_dist(p, pos[a], pos[b]) >= r + 1.0)
    }

    fn improve(&self, pos: &mut [Point], v: usize) -> bool {
        let here = pos[v];
        let mut best = (self.cost(pos, v), here);
        for p in self.candidates(pos, v) {
            if !p.x.is_finite() || !p.y.is_finite() || !self.free(pos, v, p) {
                continue;
            }
            pos[v] = p;
            let c = self.cost(pos, v);
            if better(c, best.0) {
                best = (c, p);
            }
        }
        pos[v] = best.1;
        best.1 != here
    }
}

#[cfg(test)]
#[path = "reduce_tests.rs"]
mod tests;
