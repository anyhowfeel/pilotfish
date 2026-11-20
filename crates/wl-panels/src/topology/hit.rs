//! Hit-testing on screen-space geometry (pure).

use wl_kit::egui::Pos2;

/// Distance from `p` to the segment `a`-`b`.
pub fn dist_to_segment(p: Pos2, a: Pos2, b: Pos2) -> f32 {
    let ab = b - a;
    let len2 = ab.length_sq();
    if len2 < 1e-6 {
        return (p - a).length();
    }
    let t = ((p - a).dot(ab) / len2).clamp(0.0, 1.0);
    (p - (a + ab * t)).length()
}

/// Topmost node whose disc (grown by `slop`) contains `p`; the smallest disc wins on overlap.
pub fn node_at(discs: &[(Pos2, f32)], p: Pos2, slop: f32) -> Option<usize> {
    discs
        .iter()
        .enumerate()
        .filter(|(_, (c, r))| (p - *c).length() <= r + slop)
        .min_by(|a, b| a.1.1.total_cmp(&b.1.1))
        .map(|(i, _)| i)
}

/// Closest segment within `tol` of `p`; segments are `(a, b, half_width)` by link index.
pub fn edge_at(segs: &[(Pos2, Pos2, f32)], p: Pos2, tol: f32) -> Option<usize> {
    segs.iter()
        .enumerate()
        .map(|(i, (a, b, w))| (i, dist_to_segment(p, *a, *b) - w))
        .filter(|(_, d)| *d <= tol)
        .min_by(|a, b| a.1.total_cmp(&b.1))
        .map(|(i, _)| i)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wl_kit::egui::pos2;

    #[test]
    fn segment_distance_clamps_to_endpoints() {
        let (a, b) = (pos2(0.0, 0.0), pos2(10.0, 0.0));
        assert_eq!(dist_to_segment(pos2(5.0, 3.0), a, b), 3.0);
        assert_eq!(dist_to_segment(pos2(-4.0, 3.0), a, b), 5.0);
        assert_eq!(dist_to_segment(pos2(1.0, 1.0), a, a), 2.0_f32.sqrt());
    }

    #[test]
    fn smallest_disc_wins_and_slop_applies() {
        let d = [(pos2(0.0, 0.0), 20.0), (pos2(5.0, 0.0), 6.0)];
        assert_eq!(node_at(&d, pos2(4.0, 0.0), 0.0), Some(1));
        assert_eq!(node_at(&d, pos2(-24.0, 0.0), 0.0), None);
        assert_eq!(node_at(&d, pos2(-24.0, 0.0), 5.0), Some(0));
    }

    #[test]
    fn nearest_edge_within_tolerance() {
        let s = [
            (pos2(0.0, 0.0), pos2(100.0, 0.0), 1.0),
            (pos2(0.0, 10.0), pos2(100.0, 10.0), 1.0),
        ];
        assert_eq!(edge_at(&s, pos2(50.0, 8.0), 4.0), Some(1));
        assert_eq!(edge_at(&s, pos2(50.0, 40.0), 4.0), None);
    }
}
