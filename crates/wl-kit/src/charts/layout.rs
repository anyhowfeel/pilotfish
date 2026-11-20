//! Pure layout math for painted charts.

/// Widths of proportional segments: separated by `gap`, each at least `min_w` (if value > 0),
/// summing exactly to `total` (including gaps) when any value is positive.
pub fn segment_widths(values: &[f64], total: f32, gap: f32, min_w: f32) -> Vec<f32> {
    let sum: f64 = values.iter().filter(|v| **v > 0.0).sum();
    let n = values.iter().filter(|v| **v > 0.0).count();
    if sum <= 0.0 || n == 0 {
        return vec![0.0; values.len()];
    }
    let avail = (total - gap * (n as f32 - 1.0)).max(0.0);
    let raw: Vec<f32> = values
        .iter()
        .map(|v| {
            if *v > 0.0 {
                (*v / sum) as f32 * avail
            } else {
                0.0
            }
        })
        .collect();
    // Lift tiny segments to min_w, taking the space from the big ones.
    let lifted: f32 = raw
        .iter()
        .filter(|w| **w > 0.0 && **w < min_w)
        .map(|w| min_w - w)
        .sum();
    let big: f32 = raw.iter().filter(|w| **w >= min_w).sum();
    let k = if big > lifted {
        (big - lifted) / big
    } else {
        1.0
    };
    raw.iter()
        .map(|&w| {
            if w <= 0.0 {
                0.0
            } else if w < min_w {
                min_w
            } else {
                w * k
            }
        })
        .collect()
}

/// Fraction (0..=1) of `v` relative to `max`.
pub fn fraction(v: f64, max: f64) -> f32 {
    if max > 0.0 && v.is_finite() {
        (v / max).clamp(0.0, 1.0) as f32
    } else {
        0.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn widths_sum_to_total() {
        let w = segment_widths(&[50.0, 30.0, 20.0], 302.0, 1.0, 3.0);
        assert!((w.iter().sum::<f32>() + 2.0 - 302.0).abs() < 0.01);
        assert!(w[0] > w[1] && w[1] > w[2]);
    }

    #[test]
    fn tiny_segments_get_min_width() {
        let w = segment_widths(&[1000.0, 1.0, 0.0], 200.0, 2.0, 4.0);
        assert_eq!(w[1], 4.0);
        assert_eq!(w[2], 0.0);
        assert!((w.iter().sum::<f32>() + 2.0 - 200.0).abs() < 0.01);
    }

    #[test]
    fn empty_and_zero() {
        assert_eq!(segment_widths(&[], 100.0, 2.0, 3.0), Vec::<f32>::new());
        assert_eq!(segment_widths(&[0.0, 0.0], 100.0, 2.0, 3.0), vec![0.0, 0.0]);
    }

    #[test]
    fn fractions() {
        assert_eq!(fraction(5.0, 10.0), 0.5);
        assert_eq!(fraction(5.0, 0.0), 0.0);
        assert_eq!(fraction(50.0, 10.0), 1.0);
    }
}
