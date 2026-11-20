//! Bucket width of the graph: fixed choices plus an automatic pick for the capture length.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Interval {
    Ms100,
    S1,
    S10,
    M1,
    Auto,
}

/// Steps `Auto` chooses from; the smallest one that keeps the bucket count in budget wins.
const LADDER: [f64; 10] = [0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0, 300.0, 3600.0];
/// Target upper bound of buckets drawn (keeps lines readable and passes quick).
pub const MAX_BUCKETS: f64 = 300.0;

impl Interval {
    pub const CHOICES: [(Interval, &'static str); 5] = [
        (Interval::Ms100, "100 ms"),
        (Interval::S1, "1 s"),
        (Interval::S10, "10 s"),
        (Interval::M1, "1 min"),
        (Interval::Auto, "Auto"),
    ];

    /// Seconds per bucket for a capture lasting `duration` seconds.
    pub fn seconds(self, duration: f64) -> f64 {
        match self {
            Interval::Ms100 => 0.1,
            Interval::S1 => 1.0,
            Interval::S10 => 10.0,
            Interval::M1 => 60.0,
            Interval::Auto => auto_interval(duration),
        }
    }
}

/// Smallest ladder step giving at most [`MAX_BUCKETS`] buckets (`1 s` while nothing is known).
pub fn auto_interval(duration: f64) -> f64 {
    if !duration.is_finite() || duration <= 0.0 {
        return 1.0;
    }
    LADDER
        .iter()
        .copied()
        .find(|s| duration / s <= MAX_BUCKETS)
        .unwrap_or(LADDER[LADDER.len() - 1])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_follows_the_capture_length() {
        assert_eq!(auto_interval(0.0), 1.0);
        assert_eq!(auto_interval(f64::NAN), 1.0);
        assert_eq!(auto_interval(1.6), 0.1);
        assert_eq!(auto_interval(30.0), 0.1);
        assert_eq!(auto_interval(100.0), 0.5);
        assert_eq!(auto_interval(363.0), 2.0);
        assert_eq!(auto_interval(3600.0), 30.0);
        assert_eq!(auto_interval(86_400.0), 300.0);
        assert_eq!(auto_interval(1e9), 3600.0);
    }

    #[test]
    fn fixed_choices_ignore_the_duration() {
        assert_eq!(Interval::Ms100.seconds(1e6), 0.1);
        assert_eq!(Interval::M1.seconds(0.0), 60.0);
        assert_eq!(Interval::Auto.seconds(100.0), 0.5);
    }

    #[test]
    fn auto_never_exceeds_the_bucket_budget_below_the_last_step() {
        for d in [1.0, 17.0, 250.0, 4000.0, 50_000.0] {
            assert!(d / auto_interval(d) <= MAX_BUCKETS, "{d}");
        }
    }
}
