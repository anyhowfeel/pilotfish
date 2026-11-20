//! Value units of multi-series charts and their human-readable formatting (pure, tested).

use crate::format;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unit {
    PacketsPerSec,
    BytesPerSec,
    BitsPerSec,
    Bytes,
    Seconds,
}

/// `12.3`, `123`, `1.2k`, `4.5M`: compact plain number.
pub fn compact(v: f64) -> String {
    let v = if v.is_finite() { v } else { 0.0 };
    let a = v.abs();
    if a >= 1e9 {
        format!("{:.1}G", v / 1e9)
    } else if a >= 1e6 {
        format!("{:.1}M", v / 1e6)
    } else if a >= 1e4 {
        format!("{:.0}k", v / 1e3)
    } else if a >= 1e3 {
        format!("{:.1}k", v / 1e3)
    } else if a >= 100.0 || (a - a.round()).abs() < 0.05 {
        format!("{v:.0}")
    } else {
        format!("{v:.1}")
    }
}

fn bits(v: f64) -> String {
    let v = if v.is_finite() { v.max(0.0) } else { 0.0 };
    let (div, unit) = match v {
        v if v >= 1e9 => (1e9, "Gbit/s"),
        v if v >= 1e6 => (1e6, "Mbit/s"),
        v if v >= 1e3 => (1e3, "kbit/s"),
        _ => (1.0, "bit/s"),
    };
    if div == 1.0 {
        format!("{} {unit}", v.round() as u64)
    } else {
        format!("{:.1} {unit}", v / div)
    }
}

fn seconds(v: f64) -> String {
    let v = if v.is_finite() { v.max(0.0) } else { 0.0 };
    if v >= 1.0 {
        format!("{v:.2} s")
    } else if v >= 0.001 {
        format!("{:.1} ms", v * 1e3)
    } else {
        format!("{:.0} \u{b5}s", v * 1e6)
    }
}

impl Unit {
    /// Full value with its unit ("1.2 MiB/s").
    pub fn format(self, v: f64) -> String {
        match self {
            Unit::PacketsPerSec => format!("{} pkt/s", compact(v)),
            Unit::BytesPerSec => format::rate(v),
            Unit::BitsPerSec => bits(v),
            Unit::Bytes => format::bytes(v.max(0.0) as u64),
            Unit::Seconds => seconds(v),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_numbers() {
        assert_eq!(compact(0.0), "0");
        assert_eq!(compact(7.0), "7");
        assert_eq!(compact(7.46), "7.5");
        assert_eq!(compact(120.4), "120");
        assert_eq!(compact(1234.0), "1.2k");
        assert_eq!(compact(45_000.0), "45k");
        assert_eq!(compact(2_500_000.0), "2.5M");
        assert_eq!(compact(f64::NAN), "0");
    }

    #[test]
    fn unit_formats() {
        assert_eq!(Unit::PacketsPerSec.format(12.0), "12 pkt/s");
        assert_eq!(Unit::BitsPerSec.format(999.0), "999 bit/s");
        assert_eq!(Unit::BitsPerSec.format(1_500_000.0), "1.5 Mbit/s");
        assert_eq!(Unit::Seconds.format(0.0123), "12.3 ms");
        assert_eq!(Unit::Seconds.format(0.000_045), "45 \u{b5}s");
        assert_eq!(Unit::Seconds.format(2.0), "2.00 s");
        assert_eq!(Unit::Bytes.format(840.0), "840 B");
    }
}
