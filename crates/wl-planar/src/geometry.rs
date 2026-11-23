//! Points and the exact-enough predicates the crossing count relies on.

#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct Point {
    pub x: f64,
    pub y: f64,
}

impl Point {
    pub const fn new(x: f64, y: f64) -> Self {
        Self { x, y }
    }

    pub fn dist(self, o: Point) -> f64 {
        (self.x - o.x).hypot(self.y - o.y)
    }
}

/// Twice the signed area of `abc`: positive when `c` is left of `a -> b`.
fn orient(a: Point, b: Point, c: Point) -> f64 {
    (b.x - a.x) * (c.y - a.y) - (b.y - a.y) * (c.x - a.x)
}

/// Sign of `orient`, zero when `c` is within rounding of the line (relative to the lengths).
fn side(a: Point, b: Point, c: Point) -> i8 {
    let scale = a.dist(b) * a.dist(c).max(b.dist(c));
    let o = orient(a, b, c);
    if o.abs() <= 1e-9 * scale {
        0
    } else if o > 0.0 {
        1
    } else {
        -1
    }
}

fn within(a: Point, b: Point, c: Point) -> bool {
    c.x >= a.x.min(b.x) - 1e-9
        && c.x <= a.x.max(b.x) + 1e-9
        && c.y >= a.y.min(b.y) - 1e-9
        && c.y <= a.y.max(b.y) + 1e-9
}

fn key(p: Point) -> (f64, f64) {
    (p.x, p.y)
}

/// Whether segments `ab` and `cd` cross, touch or overlap anywhere but at a shared endpoint.
/// `shared` says that the two edges are known to meet at a vertex (so that vertex is allowed); the
/// segments then only count when they run along each other.
///
/// The arguments are put in a fixed order first: the tolerance of `side` depends on the lengths it
/// sees, so without that the answer for a nearly degenerate pair could depend on which end the
/// caller listed first.
pub fn edges_cross(a: Point, b: Point, c: Point, d: Point, shared: bool) -> bool {
    let (a, b) = if key(a) <= key(b) { (a, b) } else { (b, a) };
    let (c, d) = if key(c) <= key(d) { (c, d) } else { (d, c) };
    let ((a, b), (c, d)) = if (key(a), key(b)) <= (key(c), key(d)) {
        ((a, b), (c, d))
    } else {
        ((c, d), (a, b))
    };
    if shared {
        return shared_endpoint_overlap(a, b, c, d);
    }
    let (s1, s2) = (side(a, b, c), side(a, b, d));
    let (s3, s4) = (side(c, d, a), side(c, d, b));
    if s1 != s2 && s3 != s4 && s1 * s2 <= 0 && s3 * s4 <= 0 {
        // Proper crossing, or one end lying on the other segment.
        if s1 == 0 && s2 == 0 {
            return within(a, b, c) || within(a, b, d) || within(c, d, a) || within(c, d, b);
        }
        return true;
    }
    (s1 == 0 && within(a, b, c))
        || (s2 == 0 && within(a, b, d))
        || (s3 == 0 && within(c, d, a))
        || (s4 == 0 && within(c, d, b))
}

/// Two edges meeting at a vertex overlap when they leave it in the same direction.
fn shared_endpoint_overlap(a: Point, b: Point, c: Point, d: Point) -> bool {
    let (p, x, y) = if a == c {
        (a, b, d)
    } else if a == d {
        (a, b, c)
    } else if b == c {
        (b, a, d)
    } else {
        (b, a, c)
    };
    side(p, x, y) == 0 && ((x.x - p.x) * (y.x - p.x) + (x.y - p.y) * (y.y - p.y)) > 0.0
}

#[cfg(test)]
#[path = "geometry_tests.rs"]
mod tests;
