//! A uniform grid of buckets over the plane, for finding what lies near a point or a segment.

use crate::geometry::Point;

/// The corners of the smallest box around `pts`, both at the origin when there are none.
pub fn bounds(pts: &[Point]) -> (Point, Point) {
    let mut it = pts.iter();
    let Some(first) = it.next() else {
        return (Point::default(), Point::default());
    };
    it.fold((*first, *first), |(lo, hi), p| {
        (
            Point::new(lo.x.min(p.x), lo.y.min(p.y)),
            Point::new(hi.x.max(p.x), hi.y.max(p.y)),
        )
    })
}

/// Maps coordinates to cells. Points outside the area the grid was built for are clamped to its
/// border cells, which stays correct (a segment is listed in every cell its bounding box touches,
/// clamped alike) and only costs speed.
pub struct Frame {
    x0: f64,
    y0: f64,
    inv: f64,
    nx: usize,
    ny: usize,
}

impl Frame {
    /// Cells of side `cell`, or larger so that no side has more than `max_side` of them.
    pub fn new(pts: &[Point], cell: f64, max_side: usize) -> Self {
        let (lo, hi) = bounds(pts);
        let (x0, x1, y0, y1) = (lo.x, hi.x, lo.y, hi.y);
        let extent = (x1 - x0).max(y1 - y0);
        let cell = cell.max(extent / max_side as f64).max(f64::MIN_POSITIVE);
        let count = |lo: f64, hi: f64| ((hi - lo) / cell).floor().max(0.0) as usize + 1;
        Self {
            x0,
            y0,
            inv: 1.0 / cell,
            nx: count(x0, x1),
            ny: count(y0, y1),
        }
    }

    fn index(&self, v: f64, lo: f64, n: usize) -> usize {
        (((v - lo) * self.inv).floor().max(0.0) as usize).min(n - 1)
    }

    /// Calls `f` with every cell that the segment `ab` touches, or comes within `margin` of: the
    /// columns it spans, and in each the rows covered by its part inside the column.
    fn walk(&self, a: Point, b: Point, margin: f64, mut f: impl FnMut(usize)) {
        let (a, b) = if a.x <= b.x { (a, b) } else { (b, a) };
        // Rounding must never drop a cell, or two crossing segments could miss each other.
        let m = margin + 1e-6 / self.inv;
        let (i0, i1) = (
            self.index(a.x - m, self.x0, self.nx),
            self.index(b.x + m, self.x0, self.nx),
        );
        let cell = 1.0 / self.inv;
        for i in i0..=i1 {
            let from = if i == i0 {
                a.x
            } else {
                a.x.max(self.x0 + i as f64 * cell - m)
            };
            let to = if i == i1 {
                b.x
            } else {
                b.x.min(self.x0 + (i + 1) as f64 * cell + m)
            };
            let y_at = |x: f64| {
                if b.x > a.x {
                    a.y + (b.y - a.y) * (x - a.x) / (b.x - a.x)
                } else {
                    a.y
                }
            };
            let (ya, yb) = if b.x > a.x {
                (y_at(from), y_at(to))
            } else {
                (a.y, b.y)
            };
            let j0 = self.index(ya.min(yb) - m, self.y0, self.ny);
            let j1 = self.index(ya.max(yb) + m, self.y0, self.ny);
            for j in j0..=j1 {
                f(j * self.nx + i);
            }
        }
    }
}

/// Ids filed under the cells their segment (or point) touches.
pub struct Buckets {
    frame: Frame,
    cells: Vec<Vec<u32>>,
}

impl Buckets {
    pub fn new(frame: Frame) -> Self {
        let cells = vec![Vec::new(); frame.nx * frame.ny];
        Self { frame, cells }
    }

    /// Files `id` under the segment `ab`; a point is the segment `aa`.
    pub fn add(&mut self, a: Point, b: Point, id: u32) {
        let cells = &mut self.cells;
        self.frame.walk(a, b, 0.0, |c| cells[c].push(id));
    }

    /// `a` and `b` must be what the id was added with.
    pub fn remove(&mut self, a: Point, b: Point, id: u32) {
        let cells = &mut self.cells;
        self.frame.walk(a, b, 0.0, |c| {
            if let Some(i) = cells[c].iter().position(|&x| x == id) {
                cells[c].swap_remove(i);
            }
        });
    }

    /// Appends the ids filed anywhere within `margin` of the segment `ab`, and possibly some
    /// farther; an id may come up more than once.
    pub fn gather(&self, a: Point, b: Point, margin: f64, out: &mut Vec<u32>) {
        self.frame
            .walk(a, b, margin, |c| out.extend_from_slice(&self.cells[c]));
    }
}

#[cfg(test)]
#[path = "grid_tests.rs"]
mod tests;
