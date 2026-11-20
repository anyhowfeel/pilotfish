//! What a graph series measures, and how bucket data becomes plotted values (pure, tested).

use wl_kit::charts::Unit;
use wl_model::{DeltaStat, IoSeries};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Metric {
    PacketsPerSec,
    BytesPerSec,
    BitsPerSec,
    AvgPacketSize,
    MaxDelta,
    MinDelta,
}

impl Metric {
    pub const ALL: [Metric; 6] = [
        Metric::PacketsPerSec,
        Metric::BytesPerSec,
        Metric::BitsPerSec,
        Metric::AvgPacketSize,
        Metric::MaxDelta,
        Metric::MinDelta,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Metric::PacketsPerSec => "Packets/s",
            Metric::BytesPerSec => "Bytes/s",
            Metric::BitsPerSec => "Bits/s",
            Metric::AvgPacketSize => "Avg packet size",
            Metric::MaxDelta => "Max frame delta",
            Metric::MinDelta => "Min frame delta",
        }
    }

    pub fn unit(self) -> Unit {
        match self {
            Metric::PacketsPerSec => Unit::PacketsPerSec,
            Metric::BytesPerSec => Unit::BytesPerSec,
            Metric::BitsPerSec => Unit::BitsPerSec,
            Metric::AvgPacketSize => Unit::Bytes,
            Metric::MaxDelta | Metric::MinDelta => Unit::Seconds,
        }
    }

    /// The extra tshark column this metric needs, if any.
    pub fn delta(self) -> Option<DeltaStat> {
        match self {
            Metric::MaxDelta => Some(DeltaStat::Max),
            Metric::MinDelta => Some(DeltaStat::Min),
            _ => None,
        }
    }

    /// Plotted value of bucket `i` (`NaN` = no data: average and delta of an empty bucket).
    pub fn value(self, s: &IoSeries, i: usize, interval: f64) -> f64 {
        let packets = s.packets.get(i).copied().unwrap_or(0);
        let bytes = s.bytes.get(i).copied().unwrap_or(0) as f64;
        match self {
            Metric::PacketsPerSec => packets as f64 / interval,
            Metric::BytesPerSec => bytes / interval,
            Metric::BitsPerSec => bytes * 8.0 / interval,
            _ if packets == 0 => f64::NAN,
            Metric::AvgPacketSize => bytes / packets as f64,
            Metric::MaxDelta | Metric::MinDelta => s.delta.get(i).copied().unwrap_or(f64::NAN),
        }
    }

    /// All plotted values of a series.
    pub fn values(self, s: &IoSeries, interval: f64) -> Vec<f64> {
        (0..s.packets.len())
            .map(|i| self.value(s, i, interval))
            .collect()
    }
}

/// Packets and bytes of the buckets whose centre lies inside `[from, to]`.
pub fn window_totals(s: &IoSeries, interval: f64, from: f64, to: f64) -> (u64, u64) {
    (0..s.packets.len())
        .filter(|i| {
            let mid = (*i as f64 + 0.5) * interval;
            mid >= from && mid <= to
        })
        .fold((0, 0), |(p, b), i| (p + s.packets[i], b + s.bytes[i]))
}

/// Packets and bytes of the whole series.
pub fn totals(s: &IoSeries) -> (u64, u64) {
    (s.packets.iter().sum(), s.bytes.iter().sum())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn series() -> IoSeries {
        IoSeries {
            packets: vec![4, 0, 2],
            bytes: vec![400, 0, 1000],
            delta: vec![0.5, 0.0, 0.1],
            error: None,
        }
    }

    #[test]
    fn rate_metrics_divide_by_the_interval() {
        let s = series();
        assert_eq!(Metric::PacketsPerSec.value(&s, 0, 2.0), 2.0);
        assert_eq!(Metric::BytesPerSec.value(&s, 0, 2.0), 200.0);
        assert_eq!(Metric::BitsPerSec.value(&s, 0, 0.5), 6400.0);
        assert_eq!(Metric::PacketsPerSec.value(&s, 1, 1.0), 0.0);
    }

    #[test]
    fn average_and_delta_leave_gaps_in_empty_buckets() {
        let s = series();
        assert_eq!(Metric::AvgPacketSize.value(&s, 0, 1.0), 100.0);
        assert_eq!(Metric::AvgPacketSize.value(&s, 2, 1.0), 500.0);
        assert!(Metric::AvgPacketSize.value(&s, 1, 1.0).is_nan());
        assert!(Metric::MaxDelta.value(&s, 1, 1.0).is_nan());
        assert_eq!(Metric::MaxDelta.value(&s, 2, 1.0), 0.1);
        assert_eq!(Metric::MinDelta.values(&s, 1.0).len(), 3);
    }

    #[test]
    fn only_delta_metrics_need_the_extra_column() {
        let with: Vec<_> = Metric::ALL.iter().filter(|m| m.delta().is_some()).collect();
        assert_eq!(with.len(), 2);
    }

    #[test]
    fn window_totals_use_bucket_centres() {
        let s = series();
        assert_eq!(window_totals(&s, 1.0, 0.0, 1.0), (4, 400));
        assert_eq!(window_totals(&s, 1.0, 1.0, 3.0), (2, 1000));
        assert_eq!(window_totals(&s, 1.0, 0.0, 3.0), totals(&s));
        assert_eq!(window_totals(&s, 1.0, 5.0, 6.0), (0, 0));
    }
}
