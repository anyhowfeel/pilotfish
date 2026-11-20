//! Unit tests (kept in their own file to respect the 250-line limit).
use super::*;

#[test]
fn columns_always_fit_their_width() {
    for w in [430.0_f32, 560.0, 640.0, 700.0, 760.0, 880.0, 960.0, 1100.0] {
        let c = Cols::for_width(w);
        assert!(c.min_width() <= w, "{w}: needs {}", c.min_width());
        assert_eq!(c.heads().len(), c.count(), "{w}");
    }
}
