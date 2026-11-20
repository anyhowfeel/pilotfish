//! Pure scale functions: bytes -> visual size / opacity (log scale keeps 100:1 readable).

/// Smallest and largest node radius in world units.
pub const R_MIN: f32 = 5.0;
pub const R_MAX: f32 = 17.0;
pub const W_MIN: f32 = 1.0;
pub const W_MAX: f32 = 5.0;
pub const ALPHA_MIN: u8 = 70;
pub const ALPHA_MAX: u8 = 225;

/// Log-scale normalisation of byte counts onto `0..=1` between `lo` and `hi`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LogScale {
    lo: f64,
    hi: f64,
}

impl LogScale {
    pub fn new(min: u64, max: u64) -> Self {
        Self {
            lo: min.max(1) as f64,
            hi: max.max(1) as f64,
        }
    }

    /// `0` at the lightest edge, `1` at the heaviest; a single-valued range maps to `1`.
    pub fn norm(&self, bytes: u64) -> f32 {
        if self.hi <= self.lo {
            return 1.0;
        }
        let t = ((bytes.max(1) as f64).ln() - self.lo.ln()) / (self.hi.ln() - self.lo.ln());
        t.clamp(0.0, 1.0) as f32
    }

    /// The byte value at normalised position `t` (inverse of `norm`).
    pub fn value_at(&self, t: f32) -> u64 {
        (self.lo.ln() + f64::from(t) * (self.hi.ln() - self.lo.ln())).exp() as u64
    }
}

pub fn lerp(a: f32, b: f32, t: f32) -> f32 {
    a + (b - a) * t
}

/// Node radius grows with the square root of the bytes (area ~ traffic).
pub fn node_radius(bytes: u64, max: u64) -> f32 {
    let t = if max == 0 {
        0.0
    } else {
        (bytes as f64 / max as f64).sqrt() as f32
    };
    lerp(R_MIN, R_MAX, t.clamp(0.0, 1.0))
}

pub fn edge_width(t: f32) -> f32 {
    lerp(W_MIN, W_MAX, t)
}

pub fn edge_alpha(t: f32) -> u8 {
    lerp(f32::from(ALPHA_MIN), f32::from(ALPHA_MAX), t).round() as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_scale_keeps_hundred_to_one_readable() {
        let s = LogScale::new(1_000, 100_000);
        assert_eq!(s.norm(1_000), 0.0);
        assert_eq!(s.norm(100_000), 1.0);
        assert!((s.norm(10_000) - 0.5).abs() < 1e-6);
        let (w_lo, w_hi) = (edge_width(s.norm(1_000)), edge_width(s.norm(100_000)));
        assert!(w_hi / w_lo >= 4.0 && w_hi <= W_MAX);
    }

    #[test]
    fn degenerate_range_is_full_intensity() {
        assert_eq!(LogScale::new(500, 500).norm(500), 1.0);
        assert_eq!(LogScale::new(0, 0).norm(0), 1.0);
    }

    #[test]
    fn value_at_inverts_norm() {
        let s = LogScale::new(100, 1_000_000);
        assert!((9_000..=11_000).contains(&s.value_at(0.5)));
    }

    #[test]
    fn radius_is_sqrt_scaled_and_bounded() {
        assert_eq!(node_radius(0, 100), R_MIN);
        assert_eq!(node_radius(100, 100), R_MAX);
        let quarter = node_radius(25, 100);
        assert!((quarter - lerp(R_MIN, R_MAX, 0.5)).abs() < 1e-4);
        assert_eq!(node_radius(5, 0), R_MIN);
    }

    #[test]
    fn alpha_is_monotonic() {
        assert!(edge_alpha(0.0) < edge_alpha(0.5) && edge_alpha(0.5) < edge_alpha(1.0));
        assert_eq!(edge_alpha(1.0), ALPHA_MAX);
    }
}
