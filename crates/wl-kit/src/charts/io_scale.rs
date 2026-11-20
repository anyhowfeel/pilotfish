//! Scale maths of the multi-series chart: log-Y transform, log ticks, hover bucket (pure).

/// Plot-space Y of a value. Log mode uses `log10(1 + v)` so zero stays at the baseline.
pub fn to_plot(v: f64, log: bool) -> f64 {
    if log { (1.0 + v.max(0.0)).log10() } else { v }
}

/// Inverse of [`to_plot`].
pub fn from_plot(y: f64, log: bool) -> f64 {
    if log { 10f64.powf(y) - 1.0 } else { y }
}

/// Values (not plot coordinates) of the log grid lines up to `max`: 0, 1, 10, 100, ...
pub fn log_ticks(max: f64) -> Vec<f64> {
    let mut v = vec![0.0];
    let mut t = 1.0;
    while t <= max.max(1.0) * 1.0001 {
        v.push(t);
        t *= 10.0;
    }
    v
}

/// Index of the bucket under X (`[i * interval, (i + 1) * interval)`), if inside `0..n`.
pub fn bucket_at(x: f64, interval: f64, n: usize) -> Option<usize> {
    if !x.is_finite() || interval <= 0.0 || x < 0.0 {
        return None;
    }
    let i = (x / interval).floor() as usize;
    (i < n).then_some(i)
}

/// Breaks `values` into runs of finite values `(start_index, run)`: NaN is a gap in the line.
pub fn runs(values: &[f64]) -> Vec<(usize, &[f64])> {
    let mut out = Vec::new();
    let mut start = None;
    for (i, v) in values.iter().enumerate() {
        match (v.is_finite(), start) {
            (true, None) => start = Some(i),
            (false, Some(s)) => {
                out.push((s, &values[s..i]));
                start = None;
            }
            _ => {}
        }
    }
    if let Some(s) = start {
        out.push((s, &values[s..]));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_roundtrip_keeps_zero_at_baseline() {
        assert_eq!(to_plot(0.0, true), 0.0);
        assert!((to_plot(9.0, true) - 1.0).abs() < 1e-12);
        for v in [0.0, 1.0, 37.5, 1e6] {
            assert!((from_plot(to_plot(v, true), true) - v).abs() < 1e-6 * v.max(1.0));
        }
        assert_eq!(to_plot(5.0, false), 5.0);
        assert_eq!(to_plot(-3.0, true), 0.0);
    }

    #[test]
    fn log_ticks_are_decades() {
        assert_eq!(log_ticks(1000.0), vec![0.0, 1.0, 10.0, 100.0, 1000.0]);
        assert_eq!(log_ticks(0.0), vec![0.0, 1.0]);
        assert_eq!(log_ticks(50.0), vec![0.0, 1.0, 10.0]);
    }

    #[test]
    fn hover_bucket() {
        assert_eq!(bucket_at(0.0, 1.0, 5), Some(0));
        assert_eq!(bucket_at(2.99, 1.0, 5), Some(2));
        assert_eq!(bucket_at(5.0, 1.0, 5), None);
        assert_eq!(bucket_at(-0.1, 1.0, 5), None);
        assert_eq!(bucket_at(0.35, 0.1, 100), Some(3));
        assert_eq!(bucket_at(f64::NAN, 1.0, 5), None);
    }

    #[test]
    fn runs_split_on_gaps() {
        let v = [1.0, 2.0, f64::NAN, 3.0, f64::NAN, f64::NAN, 4.0, 5.0];
        let r = runs(&v);
        assert_eq!(r.len(), 3);
        assert_eq!((r[0].0, r[0].1.len()), (0, 2));
        assert_eq!((r[1].0, r[1].1), (3, &[3.0][..]));
        assert_eq!(r[2].0, 6);
        assert!(runs(&[]).is_empty());
    }
}
