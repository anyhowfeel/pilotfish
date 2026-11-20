//! Per-interface live traffic: current rate plus a short history for the card sparkline.
//! Sampled by the app (~1 Hz while the Setup page is visible); this module is pure data.

use std::collections::HashMap;

/// Samples kept per interface (one per second).
pub const HISTORY: usize = 30;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Activity {
    /// Bytes per second (rx + tx) of the latest sample.
    pub rate: f64,
    /// Oldest first, at most `HISTORY` entries.
    pub history: Vec<f32>,
}

impl Activity {
    pub fn push(&mut self, rate: f64) {
        self.rate = rate.max(0.0);
        if self.history.len() == HISTORY {
            self.history.remove(0);
        }
        self.history.push(self.rate as f32);
    }
}

/// Interface name -> activity.
pub type ActivityMap = HashMap<String, Activity>;

/// Heights in `0..=1` for a sparkline, scaled to the busiest sample (a flat line stays at 0).
pub fn normalized(history: &[f32]) -> Vec<f32> {
    let max = history.iter().copied().fold(0.0_f32, f32::max);
    history
        .iter()
        .map(|&v| if max > 0.0 { v / max } else { 0.0 })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn history_is_bounded_and_rate_is_latest() {
        let mut a = Activity::default();
        for i in 0..(HISTORY + 5) {
            a.push(i as f64);
        }
        assert_eq!(a.history.len(), HISTORY);
        assert_eq!(a.rate, (HISTORY + 4) as f64);
        assert_eq!(a.history[0], 5.0);
        a.push(-3.0);
        assert_eq!(a.rate, 0.0);
    }

    #[test]
    fn normalizes_to_peak() {
        assert_eq!(normalized(&[1.0, 2.0, 4.0]), vec![0.25, 0.5, 1.0]);
        assert_eq!(normalized(&[0.0, 0.0]), vec![0.0, 0.0]);
        assert!(normalized(&[]).is_empty());
    }
}
