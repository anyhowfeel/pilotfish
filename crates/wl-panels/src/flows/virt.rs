//! Virtualisation maths for the fixed-height rows of the flow graph (O(1), no allocation).

use std::ops::Range;

/// Rows intersecting the viewport `[offset, offset + view_h)`, plus one row of overscan.
pub fn visible_range(offset: f32, view_h: f32, row_h: f32, n: usize) -> Range<usize> {
    if n == 0 || row_h <= 0.0 {
        return 0..0;
    }
    let first = (offset.max(0.0) / row_h).floor() as usize;
    let last = ((offset.max(0.0) + view_h.max(0.0)) / row_h).ceil() as usize + 1;
    first.min(n)..last.min(n)
}

/// Row under `y` (content coordinates).
pub fn row_at(y: f32, row_h: f32, n: usize) -> Option<usize> {
    (y >= 0.0 && row_h > 0.0)
        .then(|| (y / row_h) as usize)
        .filter(|i| *i < n)
}

/// New scroll offset that reveals row `idx` (`None` when already fully visible).
pub fn reveal(idx: usize, offset: f32, view_h: f32, row_h: f32) -> Option<f32> {
    let (top, bottom) = (idx as f32 * row_h, (idx + 1) as f32 * row_h);
    if top < offset {
        Some(top)
    } else if bottom > offset + view_h {
        Some((bottom - view_h).max(0.0))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_is_small_for_huge_lists() {
        let r = visible_range(1_000_000.0, 600.0, 32.0, 100_000);
        assert_eq!(r.start, 31_250);
        assert!(r.len() <= 21, "{r:?}");
    }

    #[test]
    fn range_is_clamped() {
        assert_eq!(visible_range(0.0, 100.0, 32.0, 2), 0..2);
        assert_eq!(visible_range(10_000.0, 100.0, 32.0, 5), 5..5);
        assert_eq!(visible_range(0.0, 100.0, 32.0, 0), 0..0);
        assert_eq!(visible_range(-50.0, 64.0, 32.0, 10), 0..3);
    }

    #[test]
    fn row_lookup() {
        assert_eq!(row_at(0.0, 32.0, 3), Some(0));
        assert_eq!(row_at(95.9, 32.0, 3), Some(2));
        assert_eq!(row_at(96.0, 32.0, 3), None);
        assert_eq!(row_at(-1.0, 32.0, 3), None);
    }

    #[test]
    fn reveal_scrolls_minimally() {
        assert_eq!(reveal(2, 0.0, 100.0, 32.0), None);
        assert_eq!(reveal(5, 0.0, 100.0, 32.0), Some(92.0));
        assert_eq!(reveal(1, 100.0, 100.0, 32.0), Some(32.0));
    }
}
