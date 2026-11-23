//! What a vertex would collide with if it stood at a given place.

use super::field::Field;
use crate::geometry::{Point, edges_cross};

/// The point of the segment `ab` nearest to `p`, as the fraction of the way from `a` to `b`
/// and as a point.
pub fn closest_on_segment(p: Point, a: Point, b: Point) -> (f64, Point) {
    let (dx, dy) = (b.x - a.x, b.y - a.y);
    let len2 = dx * dx + dy * dy;
    let t = if len2 > 0.0 {
        (((p.x - a.x) * dx + (p.y - a.y) * dy) / len2).clamp(0.0, 1.0)
    } else {
        0.0
    };
    (t, Point::new(a.x + t * dx, a.y + t * dy))
}

pub fn point_segment(p: Point, a: Point, b: Point) -> f64 {
    p.dist(closest_on_segment(p, a, b).1)
}

impl Field<'_> {
    /// Whether edges `e` and `f` cross with `v` at `p`. The predicate is not exactly symmetric
    /// on near-degenerate pairs, so the arguments come in the order `crossing_pairs` uses: lower
    /// slot first, endpoints as stored. Then this agrees with `count_crossings`.
    fn cross(&self, v: usize, p: Point, e: usize, f: usize) -> bool {
        let at = |u: usize| if u == v { p } else { self.pos[u] };
        let ((a, b), (c, d)) = (self.g.endpoints(e.min(f)), self.g.endpoints(e.max(f)));
        let shared = a == c || a == d || b == c || b == d;
        edges_cross(at(a), at(b), at(c), at(d), shared)
    }

    /// The crossings of the edges at `v` if `v` stood at `p`, the others staying put, and the
    /// gap: the least distance, capped at `clear`, between `v` and a vertex or edge it does not
    /// belong to, or between an edge at `v` and a vertex it does not end at. Moves that raise
    /// the crossings or narrow the gap are refused, which also keeps the drawing away from the
    /// degenerate cases the crossing test is blind to.
    pub(super) fn measure(&mut self, v: usize, p: Point) -> (usize, f64) {
        let (g, clear) = (self.g, self.clear);
        let (inc, nb) = (g.incident(v), g.neighbors(v));
        let (mut crossings, mut gap) = (0, clear);
        for (i, (&e, &y)) in inc.iter().zip(nb).enumerate() {
            let q = self.pos[y];
            for &f in &inc[i + 1..] {
                crossings += usize::from(self.cross(v, p, e, f));
            }
            self.near_edges(p, q, 0.0);
            for &f in &self.near {
                let (c, d) = g.endpoints(f as usize);
                if f as usize != e && c != v && d != v {
                    crossings += usize::from(self.cross(v, p, e, f as usize));
                }
            }
            self.near.clear();
            self.points.gather(p, q, clear, &mut self.near);
            for &u in &self.near {
                if u as usize != v && u as usize != y {
                    gap = gap.min(point_segment(self.pos[u as usize], p, q));
                }
            }
        }
        self.near.clear();
        self.points.gather(p, p, clear, &mut self.near);
        for &u in &self.near {
            if u as usize != v {
                gap = gap.min(self.pos[u as usize].dist(p));
            }
        }
        self.near_edges(p, p, clear);
        for &f in &self.near {
            let (c, d) = g.endpoints(f as usize);
            if c != v && d != v {
                gap = gap.min(point_segment(p, self.pos[c], self.pos[d]));
            }
        }
        (crossings, gap)
    }

    /// Fills `near` with the edges filed near the segment `ab`, each once.
    fn near_edges(&mut self, a: Point, b: Point, margin: f64) {
        let mut near = std::mem::take(&mut self.near);
        near.clear();
        self.edges.gather(a, b, margin, &mut near);
        self.dedup(&mut near);
        self.near = near;
    }
}
