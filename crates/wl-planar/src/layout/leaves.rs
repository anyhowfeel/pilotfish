//! Putting the peeled trees back around the drawn core without a single new crossing.
//!
//! The trees of a core vertex fan out into the widest angle between its drawn edges. A node at
//! depth `d` sits `d` steps from the vertex, at the middle of the wedge its subtree owns, and
//! wedges are shared out in proportion to leaf counts. Sibling subtrees then live in disjoint
//! wedges and the points of one depth ring never reach the next ring, so a fan is crossing-free by
//! construction. Other parts of the drawing can still be in the way, so the step is shrunk until
//! nothing is crossed.

use std::f64::consts::TAU;

use super::peel::Peeled;
use super::shape::crosses;
use crate::geometry::Point;
use crate::graph::Graph;

/// Widest wedge a fan may use; keeps wedges convex.
const MAX_FAN: f64 = 2.6;
/// Share of the free angle a fan uses, so its edges do not hug the core edges.
const GAP_SHARE: f64 = 0.8;
const SHRINK: f64 = 0.7;
const TRIES: usize = 40;
const MAX_STEP: f64 = 10.0;
const DISC_GAP: f64 = 2.0;

pub struct Fit<'a> {
    pub radius: &'a [f64],
    pub edge_len: f64,
}

struct Unit {
    vertex: usize,
    parent: usize,
    offset: Point,
}

struct Scene<'a> {
    peeled: &'a Peeled,
    fit: &'a Fit<'a>,
    leaves: Vec<usize>,
    height: Vec<usize>,
    drawn: Vec<(usize, usize)>,
    placed: Vec<usize>,
}

/// Places every removed vertex of one connected component. Core vertices of `pos` must already be
/// drawn; a tree component gets its root at the origin.
pub fn attach(g: &Graph, peeled: &Peeled, pos: &mut [Point], fit: &Fit) {
    let mut scene = Scene::new(g, peeled, fit);
    for root in peeled.roots() {
        pos[root] = Point::default();
        scene.placed.push(root);
        scene.fan(pos, root, 0.0, TAU);
    }
    for v in (0..g.vertex_count()).filter(|&v| peeled.core[v] && !peeled.children(v).is_empty()) {
        let (centre, free) = widest_gap(g, peeled, pos, v);
        scene.fan(pos, v, centre, (free * GAP_SHARE).min(MAX_FAN));
    }
}

/// Direction and size of the largest angle between the drawn core edges at `v`.
fn widest_gap(g: &Graph, peeled: &Peeled, pos: &[Point], v: usize) -> (f64, f64) {
    let mut angles: Vec<f64> = g
        .neighbors(v)
        .iter()
        .filter(|&&w| peeled.core[w])
        .map(|&w| (pos[w].y - pos[v].y).atan2(pos[w].x - pos[v].x))
        .collect();
    angles.sort_by(f64::total_cmp);
    let k = angles.len();
    if k < 2 {
        return (
            angles.first().map_or(0.0, |a| a + std::f64::consts::PI),
            TAU,
        );
    }
    let gap = |i: usize| {
        let next = if i + 1 < k {
            angles[i + 1]
        } else {
            angles[0] + TAU
        };
        next - angles[i]
    };
    let best = (0..k).fold(0, |b, i| if gap(i) > gap(b) { i } else { b });
    (angles[best] + gap(best) / 2.0, gap(best))
}

impl<'a> Scene<'a> {
    fn new(g: &Graph, peeled: &'a Peeled, fit: &'a Fit<'a>) -> Self {
        let n = g.vertex_count();
        let mut s = Scene {
            peeled,
            fit,
            leaves: vec![1; n],
            height: vec![0; n],
            drawn: g
                .valid_edges()
                .map(|e| g.endpoints(e))
                .filter(|&(a, b)| peeled.core[a] && peeled.core[b])
                .collect(),
            placed: (0..n).filter(|&v| peeled.core[v]).collect(),
        };
        let core_with_trees = (0..n).filter(|&v| peeled.core[v]);
        for v in peeled.order.iter().copied().chain(core_with_trees) {
            let kids = peeled.children(v);
            if !kids.is_empty() {
                s.leaves[v] = kids.iter().map(|&c| s.leaves[c]).sum();
                s.height[v] = 1 + kids.iter().map(|&c| s.height[c]).max().unwrap_or(0);
            }
        }
        s
    }

    fn fan(&mut self, pos: &mut [Point], v: usize, centre: f64, width: f64) {
        let units = self.units(v, centre, width);
        if units.is_empty() {
            return;
        }
        let rmax = units
            .iter()
            .map(|u| self.fit.radius[u.vertex])
            .fold(0.0, f64::max);
        let arc = width.max(1e-3) * self.height[v].max(1) as f64;
        let needed = (2.0 * rmax + 2.0 * DISC_GAP) * self.leaves[v] as f64 / arc;
        let len = self.fit.edge_len;
        let mut step = len.max(needed).min(MAX_STEP * len);
        let (origin, mut best) = (pos[v], None);
        for _ in 0..TRIES {
            place(pos, origin, &units, step);
            if self.crossing_free(pos, &units) {
                if self.discs_clear(pos, &units) {
                    best = Some(step);
                    break;
                }
                best.get_or_insert(step);
            }
            step *= SHRINK;
        }
        place(pos, origin, &units, best.unwrap_or(step));
        self.drawn
            .extend(units.iter().map(|u| (u.parent, u.vertex)));
        self.placed.extend(units.iter().map(|u| u.vertex));
    }

    /// The subtree of `v` as unit offsets: one step per depth, at the middle of the wedge.
    fn units(&self, v: usize, centre: f64, width: f64) -> Vec<Unit> {
        let mut out = Vec::new();
        let mut stack = Vec::new();
        self.split(v, 1, centre - width / 2.0, centre + width / 2.0, &mut stack);
        while let Some((c, depth, lo, hi)) = stack.pop() {
            let mid = (lo + hi) / 2.0;
            let d = depth as f64;
            out.push(Unit {
                vertex: c,
                parent: self.peeled.parent[c].unwrap_or(v),
                offset: Point::new(mid.cos() * d, mid.sin() * d),
            });
            self.split(c, depth + 1, lo, hi, &mut stack);
        }
        out
    }

    fn split(
        &self,
        v: usize,
        depth: usize,
        lo: f64,
        hi: f64,
        out: &mut Vec<(usize, usize, f64, f64)>,
    ) {
        let kids = self.peeled.children(v);
        let total: usize = kids.iter().map(|&c| self.leaves[c]).sum();
        let mut at = lo;
        for &c in kids {
            let share = (hi - lo) * self.leaves[c] as f64 / total as f64;
            out.push((c, depth, at, at + share));
            at += share;
        }
    }

    fn crossing_free(&self, pos: &[Point], units: &[Unit]) -> bool {
        units.iter().enumerate().all(|(i, u)| {
            let e = (u.parent, u.vertex);
            let older = units[..i].iter().map(|o| (o.parent, o.vertex));
            !self
                .drawn
                .iter()
                .copied()
                .chain(older)
                .any(|f| crosses(pos, e, f))
        })
    }

    fn discs_clear(&self, pos: &[Point], units: &[Unit]) -> bool {
        let r = self.fit.radius;
        let apart = |a: usize, b: usize| pos[a].dist(pos[b]) >= r[a] + r[b] + DISC_GAP;
        units.iter().enumerate().all(|(i, u)| {
            let older = units[..i].iter().map(|o| o.vertex);
            self.placed
                .iter()
                .copied()
                .chain(older)
                .all(|w| apart(u.vertex, w))
        })
    }
}

fn place(pos: &mut [Point], origin: Point, units: &[Unit], step: f64) {
    for u in units {
        pos[u.vertex] = Point::new(origin.x + u.offset.x * step, origin.y + u.offset.y * step);
    }
}

#[cfg(test)]
#[path = "leaves_tests.rs"]
mod tests;
