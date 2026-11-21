//! Human-readable number formatting (pure, unit-tested).

const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];

fn scaled(v: f64) -> String {
    let mut v = v.max(0.0);
    let mut u = 0;
    while u + 1 < UNITS.len() && v >= 1024.0 {
        v /= 1024.0;
        u += 1;
    }
    // 1023.96 KiB would print as "1024.0": promote.
    if u + 1 < UNITS.len() && u > 0 && (v * 10.0).round() >= 10240.0 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{} B", v.round() as u64)
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

pub fn bytes(n: u64) -> String {
    scaled(n as f64)
}

/// Bytes per second.
pub fn rate(bps: f64) -> String {
    format!("{}/s", scaled(if bps.is_finite() { bps } else { 0.0 }))
}

/// Integer with thousands separators: 1234567 -> "1,234,567".
pub fn count(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, ch) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

/// Seconds -> "850 ms", "12.3 s", "2m 05s", "1h 02m 03s".
pub fn duration(secs: f64) -> String {
    if !secs.is_finite() || secs <= 0.0 {
        return "0 s".into();
    }
    if secs < 1.0 {
        let ms = (secs * 1000.0).round() as u64;
        return if ms >= 1000 {
            "1.0 s".into()
        } else {
            format!("{ms} ms")
        };
    }
    if secs < 59.95 {
        return format!("{secs:.1} s");
    }
    let t = secs.round() as u64;
    let (h, m, s) = (t / 3600, t % 3600 / 60, t % 60);
    if h > 0 {
        format!("{h}h {m:02}m {s:02}s")
    } else {
        format!("{m}m {s:02}s")
    }
}

/// Elapsed time as a clock for chart axes: "0:05", "1:25", "1:02:05".
/// Like `clock`, with milliseconds when the time is not a whole second (`0:01.566`).
pub fn clock_precise(secs: f64) -> String {
    let ms = if secs.is_finite() && secs > 0.0 {
        (secs * 1000.0).round() as u64
    } else {
        0
    };
    let base = clock((ms / 1000) as f64);
    if ms % 1000 == 0 {
        base
    } else {
        format!("{base}.{:03}", ms % 1000)
    }
}

pub fn clock(secs: f64) -> String {
    let t = if secs.is_finite() && secs > 0.0 {
        secs.round() as u64
    } else {
        0
    };
    let (h, m, s) = (t / 3600, t % 3600 / 60, t % 60);
    if h > 0 {
        format!("{h}:{m:02}:{s:02}")
    } else {
        format!("{m}:{s:02}")
    }
}

/// Relative capture time, Wireshark style: "12.345678".
pub fn time_rel(secs: f64) -> String {
    format!("{:.6}", if secs.is_finite() { secs } else { 0.0 })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clock_axis_labels() {
        assert_eq!(clock(0.0), "0:00");
        assert_eq!(clock(5.2), "0:05");
        assert_eq!(clock(85.0), "1:25");
        assert_eq!(clock(3725.0), "1:02:05");
        assert_eq!(clock(f64::NAN), "0:00");
        assert_eq!(clock(-3.0), "0:00");
    }

    #[test]
    fn bytes_units() {
        assert_eq!(bytes(0), "0 B");
        assert_eq!(bytes(1023), "1023 B");
        assert_eq!(bytes(1024), "1.0 KiB");
        assert_eq!(bytes(1536), "1.5 KiB");
        assert_eq!(bytes(5 * 1024 * 1024), "5.0 MiB");
        assert_eq!(bytes(u64::MAX), "16384.0 PiB");
    }

    #[test]
    fn bytes_rounding_promotes() {
        assert_eq!(bytes(1024 * 1024 - 1), "1.0 MiB");
        assert_eq!(bytes(1024 * 1024 - 60), "1023.9 KiB");
    }

    #[test]
    fn rates() {
        assert_eq!(rate(1536.0), "1.5 KiB/s");
        assert_eq!(rate(0.0), "0 B/s");
        assert_eq!(rate(f64::NAN), "0 B/s");
        assert_eq!(rate(-5.0), "0 B/s");
    }

    #[test]
    fn counts() {
        assert_eq!(count(0), "0");
        assert_eq!(count(999), "999");
        assert_eq!(count(1000), "1,000");
        assert_eq!(count(1234567), "1,234,567");
    }

    #[test]
    fn durations() {
        assert_eq!(duration(0.0), "0 s");
        assert_eq!(duration(0.85), "850 ms");
        assert_eq!(duration(0.9996), "1.0 s");
        assert_eq!(duration(12.34), "12.3 s");
        assert_eq!(duration(59.97), "1m 00s");
        assert_eq!(duration(125.0), "2m 05s");
        assert_eq!(duration(3723.0), "1h 02m 03s");
    }

    #[test]
    fn time_rel_six_decimals() {
        assert_eq!(time_rel(12.3456789), "12.345679");
        assert_eq!(time_rel(0.0), "0.000000");
    }
}
