//! Elapsed-time X axis shared by every time chart: tick marks on clock-friendly steps and
//! "m:ss" labels that gain decimals only when the visible range is short.

use egui_plot::{GridInput, GridMark};

use crate::format;

/// Candidate steps in seconds: milliseconds up to two hours.
const NICE_STEPS: [f64; 24] = [
    0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1.0, 2.0, 5.0, 10.0, 15.0, 30.0, 60.0,
    120.0, 300.0, 600.0, 900.0, 1800.0, 3600.0, 7200.0, 14400.0,
];
/// Wanted distance between X labels in screen points.
const LABEL_SPACING_PT: f64 = 90.0;
/// egui_plot's default minimum grid spacing in points (what `base_step_size` is scaled by).
const MIN_GRID_PT: f64 = 8.0;
/// Space kept free at the right edge so the last label is never cut off.
const EDGE_MARGIN_PT: f64 = 22.0;

/// Smallest nice step of at least `wanted` seconds.
pub(super) fn pick_step(wanted: f64) -> f64 {
    NICE_STEPS
        .iter()
        .copied()
        .find(|s| *s >= wanted)
        .unwrap_or(14400.0)
}

/// Multiples of `step` inside `[lo, hi - edge_margin]`.
pub(super) fn marks(lo: f64, hi: f64, step: f64, edge_margin: f64) -> Vec<GridMark> {
    let first = (lo / step).ceil() as i64;
    let last = ((hi - edge_margin) / step).floor() as i64;
    (first..=last)
        .map(|k| GridMark {
            value: k as f64 * step,
            step_size: step,
        })
        .collect()
}

/// Tick marks ~`LABEL_SPACING_PT` apart on screen.
pub(super) fn time_ticks(input: GridInput) -> Vec<GridMark> {
    let (lo, hi) = input.bounds;
    // `base_step_size` is the value span of `MIN_GRID_PT` screen points.
    let step = pick_step(input.base_step_size * LABEL_SPACING_PT / MIN_GRID_PT);
    // A label centred on the right edge would be half clipped: leave room for it.
    let edge_margin = input.base_step_size / MIN_GRID_PT * EDGE_MARGIN_PT;
    marks(lo, hi, step, edge_margin)
}

/// Label of a tick: whole seconds as "1:25", sub-second steps with just enough decimals.
pub(super) fn label(mark: GridMark) -> String {
    let decimals = match mark.step_size {
        s if s >= 1.0 => return format::clock(mark.value),
        s if s >= 0.1 => 1,
        s if s >= 0.01 => 2,
        _ => 3,
    };
    let v = mark.value.max(0.0);
    let (m, s) = ((v / 60.0).floor() as u64, v % 60.0);
    let width = decimals + 3;
    format!("{m}:{s:0width$.decimals$}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mark(value: f64, step_size: f64) -> GridMark {
        GridMark { value, step_size }
    }

    #[test]
    fn steps_grow_with_the_wanted_spacing() {
        assert_eq!(pick_step(0.0004), 0.001);
        assert_eq!(pick_step(0.3), 0.5);
        assert_eq!(pick_step(7.0), 10.0);
        assert_eq!(pick_step(1e9), 14400.0);
    }

    #[test]
    fn marks_stay_inside_the_margin() {
        let m = marks(0.0, 10.0, 2.0, 1.0);
        let v: Vec<f64> = m.iter().map(|g| g.value).collect();
        assert_eq!(v, [0.0, 2.0, 4.0, 6.0, 8.0]);
        assert!(marks(3.2, 3.5, 1.0, 0.0).is_empty());
    }

    #[test]
    fn labels_use_clock_for_whole_seconds_and_decimals_below() {
        assert_eq!(label(mark(85.0, 5.0)), "1:25");
        assert_eq!(label(mark(0.5, 0.5)), "0:00.5");
        assert_eq!(label(mark(1.25, 0.05)), "0:01.25");
        assert_eq!(label(mark(0.004, 0.001)), "0:00.004");
        assert_eq!(label(mark(61.5, 0.5)), "1:01.5");
    }
}
