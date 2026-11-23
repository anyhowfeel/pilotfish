//! Evens out a drawing of a triangulation by Tutte's barycentric iteration, keeping it planar.
//!
//! Every inner vertex moves towards the average of its neighbours while the outer triangle stays
//! put. The limit is a planar drawing with well spread vertices. The shift method's drawing is
//! the start, with long thin triangles, and a plain step may fold one over. A drawing of a
//! triangulation is planar when every face is a properly oriented triangle, so a move is only
//! made when the faces around the vertex stay that way. The invariant holds throughout, and
//! stopping at any moment leaves a planar drawing.

use super::rot::Rot;
use crate::geometry::Point;

/// Every face must have at least this sine of its smallest angle, far above the tolerance of
/// the crossing test (1e-9), so a certified drawing also counts as crossing-free there.
const MIN_SIN: f64 = 1e-6;
/// Fractions of the way to the average that a vertex tries, the first beyond it (over-relaxation
/// converges faster).
const REACH: [f64; 5] = [1.8, 1.0, 0.5, 0.25, 0.1];

pub fn smooth(rot: &Rot, pos: &mut [Point], outer: [usize; 3], sweeps: usize) {
    if !to_equilateral(pos, outer)
        || !(0..pos.len()).all(|v| outer.contains(&v) || fits(rot, pos, v, pos[v]))
    {
        return;
    }
    for _ in 0..sweeps {
        let mut moved = 0.0f64;
        for v in (0..pos.len()).filter(|v| !outer.contains(v)) {
            let nb = rot.neighbors(v);
            let (sx, sy) = nb
                .iter()
                .fold((0.0, 0.0), |s, &w| (s.0 + pos[w].x, s.1 + pos[w].y));
            let goal = Point::new(sx / nb.len() as f64, sy / nb.len() as f64);
            let from = pos[v];
            for f in REACH {
                let to = Point::new(
                    from.x + f * (goal.x - from.x),
                    from.y + f * (goal.y - from.y),
                );
                if fits(rot, pos, v, to) {
                    moved = moved.max(from.dist(to));
                    pos[v] = to;
                    break;
                }
            }
        }
        if moved < 1e-9 {
            return;
        }
    }
}

/// Whether the faces around `v` are properly oriented triangles with `v` at `to`. The rotation
/// is read counter-clockwise, so the inner faces `w -> v -> next` are walked clockwise.
fn fits(rot: &Rot, pos: &[Point], v: usize, to: Point) -> bool {
    rot.neighbors(v).iter().all(|&w| {
        let (a, c) = (pos[w], pos[rot.next(v, w)]);
        let cross = (to.x - a.x) * (c.y - a.y) - (to.y - a.y) * (c.x - a.x);
        let longest = a.dist(to).max(to.dist(c)).max(c.dist(a));
        cross < -MIN_SIN * longest * longest
    })
}

/// The affine map that sends the outer triangle to an equilateral one, which keeps the drawing
/// planar and gives the iteration a round frame. False when the triangle is flat.
fn to_equilateral(pos: &mut [Point], outer: [usize; 3]) -> bool {
    let [a, b, c] = outer.map(|v| pos[v]);
    let det = (b.x - a.x) * (c.y - a.y) - (c.x - a.x) * (b.y - a.y);
    if det.abs() < 1e-12 {
        return false;
    }
    let side = 3.0 * (pos.len() as f64).sqrt();
    let (e1, e2) = (
        Point::new(side, 0.0),
        Point::new(side / 2.0, side * 3f64.sqrt() / 2.0),
    );
    for p in pos.iter_mut() {
        let (dx, dy) = (p.x - a.x, p.y - a.y);
        let u = (dx * (c.y - a.y) - dy * (c.x - a.x)) / det;
        let w = (dy * (b.x - a.x) - dx * (b.y - a.y)) / det;
        *p = Point::new(u * e1.x + w * e2.x, u * e1.y + w * e2.y);
    }
    true
}

#[cfg(test)]
#[path = "smooth_tests.rs"]
mod tests;
