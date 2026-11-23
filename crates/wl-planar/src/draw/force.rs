//! The energy a vertex tries to lower: its edges should have the ideal length, and vertices and
//! edges that are not its own should stay out of its way, which spreads the faces.

use super::check::closest_on_segment;
use super::field::Field;
use crate::geometry::Point;

/// A vertex repels what is nearer than this many ideal lengths: other vertices, and the edges it
/// is not on.
pub const REACH: f64 = 1.0;
/// Stiffness of the repulsion against that of an edge.
const REPEL: f64 = 0.2;
/// Longest wanted move, in ideal lengths.
const MAX_MOVE: f64 = 0.5;

impl Field<'_> {
    /// Fills `around` and `around_edges` with what can repel `v` anywhere it may move to.
    pub(super) fn gather_around(&mut self, v: usize) {
        let (p, margin) = (self.pos[v], (REACH + MAX_MOVE) * self.len);
        self.around.clear();
        self.points.gather(p, p, margin, &mut self.around);
        self.around.retain(|&u| u as usize != v);
        let mut edges = std::mem::take(&mut self.around_edges);
        edges.clear();
        self.edges.gather(p, p, margin, &mut edges);
        self.dedup(&mut edges);
        self.around_edges = edges;
        let g = self.g;
        self.around_edges.retain(|&f| {
            let (c, d) = g.endpoints(f as usize);
            c != v && d != v
        });
    }

    /// The energy with `v` at `p` and the force on `v` there, the others staying put.
    pub(super) fn evaluate(&self, v: usize, p: Point) -> (f64, Point) {
        let (l, reach) = (self.len, REACH * self.len);
        let (mut energy, mut fx, mut fy) = (0.0, 0.0, 0.0);
        let mut repel = |dist: f64, away: Point, weight: f64| {
            if dist < reach {
                let push = REPEL * (reach - dist);
                energy += 0.5 * push * (reach - dist);
                (fx, fy) = (fx + weight * push * away.x, fy + weight * push * away.y);
            }
        };
        let nb = self.g.neighbors(v);
        for &u in &self.around {
            let (d, away) = away(self.pos[u as usize], p);
            repel(d, away, 1.0);
        }
        for &f in &self.around_edges {
            let (c, d) = self.g.endpoints(f as usize);
            let near = closest_on_segment(p, self.pos[c], self.pos[d]).1;
            let (d, away) = away(near, p);
            repel(d, away, 1.0);
        }
        // An edge at `v` swings about its other end: a vertex pushing on it at fraction `t`
        // of the way to `v` pushes `v` with weight `t`.
        for &y in nb {
            for &u in self.around.iter().filter(|&&u| u as usize != y) {
                let (t, near) = closest_on_segment(self.pos[u as usize], self.pos[y], p);
                let (d, away) = away(self.pos[u as usize], near);
                repel(d, away, t);
            }
        }
        for &y in nb {
            let (d, toward) = away(self.pos[y], p);
            energy += 0.5 * (d - l).powi(2);
            (fx, fy) = (fx + toward.x * (l - d), fy + toward.y * (l - d));
        }
        (energy, Point::new(fx, fy))
    }

    /// The energy at `v`, and a move of `v` downhill of at most `MAX_MOVE` ideal lengths: the
    /// force on `v` over the stiffness of its edges.
    pub(super) fn downhill(&self, v: usize) -> (f64, Point) {
        let (energy, force) = self.evaluate(v, self.pos[v]);
        let stiff = (self.g.degree(v) + 1) as f64;
        let (mx, my) = (force.x / stiff, force.y / stiff);
        let size = mx.hypot(my);
        let cut = if size > MAX_MOVE * self.len {
            MAX_MOVE * self.len / size
        } else {
            1.0
        };
        (energy, Point::new(mx * cut, my * cut))
    }
}

/// Distance from `from` to `to` and the unit vector pointing from `from` to `to`, which is zero
/// when they coincide.
fn away(from: Point, to: Point) -> (f64, Point) {
    let (dx, dy) = (to.x - from.x, to.y - from.y);
    let d = dx.hypot(dy);
    if d > 0.0 {
        (d, Point::new(dx / d, dy / d))
    } else {
        (0.0, Point::default())
    }
}
