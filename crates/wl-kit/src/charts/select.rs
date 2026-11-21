//! Time-window selection on the throughput chart (a "scope"): pure logic, no egui.

use wl_model::RatePoint;

/// Smallest selectable window in seconds; a shorter drag is treated as a click (clears).
pub const MIN_WINDOW: f64 = 0.001;

/// A window of the capture, in seconds since its first packet (`from <= to`, millisecond
/// precision).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TimeSelection {
    pub from: f64,
    pub to: f64,
}

impl TimeSelection {
    /// Window between two drag positions (any order), rounded to the millisecond; `None` when the
    /// drag was too short to be a selection.
    pub fn from_drag(a: f64, b: f64) -> Option<Self> {
        if !a.is_finite() || !b.is_finite() || (a - b).abs() < MIN_WINDOW {
            return None;
        }
        let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
        let ms = |t: f64| (t * 1000.0).round() / 1000.0;
        let (from, to) = (ms(lo.max(0.0)), ms(hi));
        (to - from >= MIN_WINDOW).then_some(Self { from, to })
    }

    pub fn duration(&self) -> f64 {
        self.to - self.from
    }

    /// Packets and bytes of the buckets overlapping the window (whole buckets, so the figures are
    /// approximate when the buckets are wider than the window).
    pub fn totals(&self, points: &[RatePoint]) -> (u64, u64) {
        points
            .iter()
            .filter(|p| p.t + p.dt > self.from && p.t < self.to)
            .fold((0, 0), |(n, b), p| (n + u64::from(p.packets), b + p.bytes))
    }

    /// tshark display filter selecting exactly this window.
    pub fn filter_expr(&self) -> String {
        format!(
            "frame.time_relative >= {:.3} && frame.time_relative <= {:.3}",
            self.from, self.to
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pt(t: f64, packets: u32, bytes: u64) -> RatePoint {
        RatePoint {
            t,
            dt: 1.0,
            packets,
            bytes,
        }
    }

    #[test]
    fn drag_is_ordered_rounded_to_ms_and_tiny_drags_are_ignored() {
        let s = TimeSelection::from_drag(12.7004, 3.2).unwrap();
        assert_eq!((s.from, s.to), (3.2, 12.7));
        let fine = TimeSelection::from_drag(1.5662, 1.5701).unwrap();
        assert_eq!((fine.from, fine.to), (1.566, 1.570));
        assert!(TimeSelection::from_drag(5.0, 5.0004).is_none());
        assert!(TimeSelection::from_drag(f64::NAN, 5.0).is_none());
        assert_eq!(TimeSelection::from_drag(-4.0, 2.0).unwrap().from, 0.0);
    }

    #[test]
    fn totals_sum_overlapping_buckets_only() {
        let pts = [
            pt(0.0, 1, 10),
            pt(1.0, 2, 20),
            pt(2.0, 4, 40),
            pt(3.0, 8, 80),
        ];
        let s = TimeSelection { from: 1.0, to: 3.0 };
        assert_eq!(s.totals(&pts), (6, 60));
        let all = TimeSelection {
            from: 0.0,
            to: 10.0,
        };
        assert_eq!(all.totals(&pts), (15, 150));
        assert_eq!(TimeSelection { from: 8.0, to: 9.0 }.totals(&pts), (0, 0));
    }

    #[test]
    fn filter_expression_uses_frame_time_relative() {
        let s = TimeSelection {
            from: 3.0,
            to: 13.0,
        };
        assert_eq!(
            s.filter_expr(),
            "frame.time_relative >= 3.000 && frame.time_relative <= 13.000"
        );
    }
}
