//! Arranging the drawn components on one canvas: next-fit decreasing-height shelves, so the
//! largest component comes first, and the whole is centred on the origin.

use crate::geometry::Point;

/// Width over height the packing aims for.
const ASPECT: f64 = 4.0 / 3.0;

/// Top-left corner for each `(width, height)` box, boxes not overlapping, deterministic.
pub fn pack(sizes: &[(f64, f64)]) -> Vec<Point> {
    let mut order: Vec<usize> = (0..sizes.len()).collect();
    order.sort_by(|&a, &b| {
        let (p, q) = (sizes[a], sizes[b]);
        q.1.total_cmp(&p.1)
            .then(q.0.total_cmp(&p.0))
            .then(a.cmp(&b))
    });
    let area: f64 = sizes.iter().map(|s| s.0 * s.1).sum();
    let widest = sizes.iter().map(|s| s.0).fold(0.0, f64::max);
    let row = widest.max((area * ASPECT).sqrt());
    let mut out = vec![Point::default(); sizes.len()];
    let (mut x, mut y, mut shelf) = (0.0, 0.0, 0.0_f64);
    let mut extent = (0.0_f64, 0.0_f64);
    for i in order {
        let (w, h) = sizes[i];
        if x > 0.0 && x + w > row {
            y += shelf;
            (x, shelf) = (0.0, 0.0);
        }
        out[i] = Point::new(x, y);
        x += w;
        shelf = shelf.max(h);
        extent = (extent.0.max(x), extent.1.max(y + h));
    }
    for q in &mut out {
        q.x -= extent.0 / 2.0;
        q.y -= extent.1 / 2.0;
    }
    out
}

#[cfg(test)]
#[path = "pack_tests.rs"]
mod tests;
