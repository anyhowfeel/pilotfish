//! Throughput buckets whose width adapts to the capture: 1 ms at first, doubled whenever the
//! series would exceed its bucket budget, so short captures keep fine detail and long ones stay
//! bounded.

use std::collections::VecDeque;

use wl_model::RatePoint;

pub const DEFAULT_CAP: usize = 2048;
/// Finest bucket width in seconds.
const MIN_STEP: f64 = 0.001;

#[derive(Debug, Clone)]
pub struct TimeSeries {
    cap: usize,
    step: f64,
    /// Bucket index (`rel / step`) of the front element.
    base: u64,
    buckets: VecDeque<(u32, u64)>,
}

impl Default for TimeSeries {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_CAP)
    }
}

impl TimeSeries {
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            cap: cap.max(2),
            step: MIN_STEP,
            base: 0,
            buckets: VecDeque::new(),
        }
    }

    pub fn clear(&mut self) {
        self.buckets.clear();
        self.base = 0;
        self.step = MIN_STEP;
    }

    pub fn len(&self) -> usize {
        self.buckets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buckets.is_empty()
    }

    fn index(&self, rel: f64) -> u64 {
        if rel.is_finite() && rel > 0.0 {
            (rel / self.step) as u64
        } else {
            0
        }
    }

    /// Doubles the bucket width, merging neighbours.
    fn coarsen(&mut self) {
        if self.base % 2 == 1 {
            self.buckets.push_front((0, 0));
            self.base -= 1;
        }
        let merged: VecDeque<(u32, u64)> = self
            .buckets
            .make_contiguous()
            .chunks(2)
            .map(|c| {
                c.iter()
                    .fold((0u32, 0u64), |(n, b), &(p, y)| (n.saturating_add(p), b + y))
            })
            .collect();
        self.buckets = merged;
        self.base /= 2;
        self.step *= 2.0;
    }

    pub fn add(&mut self, rel: f64, bytes: u64) {
        loop {
            let idx = self.index(rel);
            if self.buckets.is_empty() {
                self.base = idx;
                self.buckets.push_back((0, 0));
                break;
            }
            let end = self.base + self.buckets.len() as u64;
            let (lo, hi) = (idx.min(self.base), idx.max(end - 1));
            if (hi - lo) as usize >= self.cap {
                self.coarsen();
                continue;
            }
            for _ in end..=idx {
                self.buckets.push_back((0, 0));
            }
            for _ in idx..self.base {
                self.buckets.push_front((0, 0));
            }
            self.base = self.base.min(idx);
            break;
        }
        let idx = self.index(rel);
        let b = &mut self.buckets[(idx - self.base) as usize];
        b.0 = b.0.saturating_add(1);
        b.1 += bytes;
    }

    pub fn points(&self) -> Vec<RatePoint> {
        self.buckets
            .iter()
            .enumerate()
            .map(|(i, &(packets, bytes))| RatePoint {
                t: (self.base + i as u64) as f64 * self.step,
                dt: self.step,
                packets,
                bytes,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn total(s: &TimeSeries) -> (u64, u64) {
        s.points()
            .iter()
            .fold((0, 0), |(n, b), p| (n + u64::from(p.packets), b + p.bytes))
    }

    #[test]
    fn starts_at_one_millisecond() {
        let mut s = TimeSeries::default();
        s.add(0.0101, 10);
        s.add(0.0109, 20);
        s.add(0.0121, 5);
        let p = s.points();
        assert_eq!(p.len(), 1 + 2);
        assert_eq!((p[0].dt, p[0].packets, p[0].bytes), (0.001, 2, 30));
        assert!((p[0].t - 0.010).abs() < 1e-9);
    }

    #[test]
    fn fills_gaps_with_zeros() {
        let mut s = TimeSeries::default();
        s.add(0.0, 1);
        s.add(0.0045, 2);
        let p = s.points();
        assert_eq!(p.len(), 5);
        assert_eq!(p[1].packets, 0);
        assert_eq!(p[4].bytes, 2);
    }

    #[test]
    fn coarsens_instead_of_growing_and_keeps_totals() {
        let mut s = TimeSeries::with_capacity(100);
        for i in 0..1000 {
            s.add(f64::from(i) * 0.001, 1);
        }
        assert!(s.len() <= 100);
        let p = s.points();
        assert!(p[0].dt >= 0.01 - 1e-12);
        assert_eq!(total(&s), (1000, 1000));
    }

    #[test]
    fn huge_jump_coarsens_without_losing_packets() {
        let mut s = TimeSeries::with_capacity(64);
        s.add(0.0, 1);
        s.add(1e6, 5);
        assert!(s.len() <= 64);
        assert_eq!(total(&s), (2, 6));
    }

    #[test]
    fn out_of_order_older_packet() {
        let mut s = TimeSeries::default();
        s.add(0.005, 1);
        s.add(0.0032, 7);
        let p = s.points();
        assert_eq!(p.len(), 3);
        assert_eq!((p[0].packets, p[0].bytes), (1, 7));
    }

    #[test]
    fn bad_rel_goes_to_zero_bucket() {
        let mut s = TimeSeries::default();
        s.add(f64::NAN, 1);
        s.add(-3.0, 1);
        let p = s.points();
        assert_eq!((p.len(), p[0].t, p[0].packets, p[0].bytes), (1, 0.0, 2, 2));
    }
}
