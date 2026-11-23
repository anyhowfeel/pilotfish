//! Moves vertices towards even edge lengths, one at a time, refusing every move that makes the
//! drawing worse.
//!
//! A vertex steps downhill on the energy of its edges and of the repulsion of what is near it.
//! The step is tried at full size, then halved until it lowers that energy and also raises
//! neither the crossings of the edges at the vertex nor narrows a gap (see `Field::measure`);
//! if no halving does, the vertex stays. A drawing that starts crossing-free therefore ends
//! crossing-free, and one with crossings never gets more.

use std::time::Instant;

use super::Relax;
use super::field::Field;
use super::grid::bounds;
use super::place::centre;
use crate::geometry::Point;
use crate::graph::Graph;

/// Halvings of a move before giving it up.
const TRIES: usize = 4;
/// A sweep that moves no vertex farther than this fraction of the ideal length ends the
/// relaxation.
const SETTLED: f64 = 1e-3;
/// Vertices moved between two looks at the clock.
const CLOCK_EVERY: usize = 8;

pub fn relax(g: &Graph, pos: &mut [Point], opts: &Relax) {
    let len = opts.ideal_len;
    if pos.is_empty() || !len.is_finite() || len <= 0.0 {
        return;
    }
    let all_free = !opts.fixed.iter().any(|&f| f);
    if all_free {
        fit(g, pos, len);
    }
    let mut field = Field::new(g, pos, len, &opts.fixed);
    for _ in 0..opts.iterations {
        let expired = || opts.deadline.is_some_and(|d| Instant::now() >= d);
        if expired() || field.sweep(&expired) < SETTLED * len {
            break;
        }
    }
    if all_free {
        fit(g, pos, len);
    }
}

/// Scales the drawing so that the mean edge has the ideal length and centres it. Both keep a
/// crossing-free drawing crossing-free.
fn fit(g: &Graph, pos: &mut [Point], len: f64) {
    let total: f64 = g
        .valid_edges()
        .map(|e| {
            let (a, b) = g.endpoints(e);
            pos[a].dist(pos[b])
        })
        .sum();
    let mean = total / g.edge_count().max(1) as f64;
    if mean.is_finite() && mean > 0.0 {
        let (lo, hi) = bounds(pos);
        let (cx, cy) = ((lo.x + hi.x) / 2.0, (lo.y + hi.y) / 2.0);
        for p in pos.iter_mut() {
            *p = Point::new((p.x - cx) * len / mean, (p.y - cy) * len / mean);
        }
    }
    centre(pos);
}

impl Field<'_> {
    /// One pass over the vertices, stopping early when `expired` says so. Returns the longest
    /// move made.
    pub fn sweep(&mut self, expired: &impl Fn() -> bool) -> f64 {
        self.index();
        let mut longest = 0.0f64;
        for v in 0..self.pos.len() {
            if v % CLOCK_EVERY == 0 && expired() {
                break;
            }
            if self.fixed.get(v).copied().unwrap_or(false) {
                continue;
            }
            self.gather_around(v);
            let from = self.pos[v];
            let (before, want) = self.downhill(v);
            let mut s = 1.0;
            for _ in 0..TRIES {
                let to = Point::new(from.x + want.x * s, from.y + want.y * s);
                if self.evaluate(v, to).0 < before && self.accepts(v, to) {
                    self.move_to(v, to);
                    longest = longest.max(from.dist(to));
                    break;
                }
                s /= 2.0;
            }
        }
        longest
    }

    fn accepts(&mut self, v: usize, to: Point) -> bool {
        let (crossings, gap) = self.measure(v, to);
        if crossings == 0 && gap >= self.clear {
            return true;
        }
        let (crossings_now, gap_now) = self.measure(v, self.pos[v]);
        crossings <= crossings_now && gap >= gap_now
    }
}

#[cfg(test)]
#[path = "relax_tests.rs"]
mod tests;
