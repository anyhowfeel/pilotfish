//! 1-second throughput buckets in a capped ring, gap-filled with zeros.

use std::collections::VecDeque;

use wl_model::RatePoint;

pub const DEFAULT_CAP: usize = 3600;

#[derive(Debug, Clone)]
pub struct TimeSeries {
    cap: usize,
    /// Bucket index (whole seconds of `rel`) of the front element.
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
            cap: cap.max(1),
            base: 0,
            buckets: VecDeque::new(),
        }
    }

    pub fn clear(&mut self) {
        self.buckets.clear();
        self.base = 0;
    }

    pub fn len(&self) -> usize {
        self.buckets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buckets.is_empty()
    }

    pub fn add(&mut self, rel: f64, bytes: u64) {
        let idx = if rel.is_finite() && rel > 0.0 {
            rel as u64
        } else {
            0
        };
        let Some(end) = self.base.checked_add(self.buckets.len() as u64) else {
            return;
        };
        if self.buckets.is_empty() {
            self.base = idx;
            self.buckets.push_back((0, 0));
        } else if idx >= end {
            if idx - end >= self.cap as u64 {
                // Huge jump: restart rather than materialise a giant gap.
                self.base = idx;
                self.buckets.clear();
                self.buckets.push_back((0, 0));
            } else {
                for _ in end..=idx {
                    self.buckets.push_back((0, 0));
                }
            }
        } else if idx < self.base {
            // Out-of-order older packet: prepend zeros if it still fits.
            let missing = (self.base - idx) as usize;
            if self.buckets.len() + missing > self.cap {
                return;
            }
            for _ in 0..missing {
                self.buckets.push_front((0, 0));
            }
            self.base = idx;
        }
        while self.buckets.len() > self.cap {
            self.buckets.pop_front();
            self.base += 1;
        }
        if idx < self.base {
            return;
        }
        let b = &mut self.buckets[(idx - self.base) as usize];
        b.0 = b.0.saturating_add(1);
        b.1 += bytes;
    }

    pub fn points(&self) -> Vec<RatePoint> {
        self.buckets
            .iter()
            .enumerate()
            .map(|(i, &(packets, bytes))| RatePoint {
                t: (self.base + i as u64) as f64,
                packets,
                bytes,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accumulates_in_bucket() {
        let mut s = TimeSeries::default();
        s.add(0.1, 10);
        s.add(0.9, 20);
        let p = s.points();
        assert_eq!(
            p,
            vec![RatePoint {
                t: 0.0,
                packets: 2,
                bytes: 30
            }]
        );
    }

    #[test]
    fn fills_gaps_with_zeros() {
        let mut s = TimeSeries::default();
        s.add(0.0, 1);
        s.add(4.5, 2);
        let p = s.points();
        assert_eq!(p.len(), 5);
        assert_eq!(
            p[1],
            RatePoint {
                t: 1.0,
                packets: 0,
                bytes: 0
            }
        );
        assert_eq!(p[4].bytes, 2);
        assert!(p.windows(2).all(|w| w[1].t - w[0].t == 1.0));
    }

    #[test]
    fn caps_ring_and_advances_base() {
        let mut s = TimeSeries::with_capacity(3);
        for i in 0..10 {
            s.add(i as f64, 1);
        }
        let p = s.points();
        assert_eq!(p.len(), 3);
        assert_eq!(p[0].t, 7.0);
        assert_eq!(p[2].t, 9.0);
    }

    #[test]
    fn huge_jump_restarts() {
        let mut s = TimeSeries::with_capacity(10);
        s.add(0.0, 1);
        s.add(1e9, 5);
        assert_eq!(s.len(), 1);
        assert_eq!(s.points()[0].t, 1e9);
    }

    #[test]
    fn out_of_order_older_packet() {
        let mut s = TimeSeries::default();
        s.add(5.0, 1);
        s.add(3.2, 7);
        let p = s.points();
        assert_eq!(p.len(), 3);
        assert_eq!(
            p[0],
            RatePoint {
                t: 3.0,
                packets: 1,
                bytes: 7
            }
        );
    }

    #[test]
    fn bad_rel_goes_to_zero_bucket() {
        let mut s = TimeSeries::default();
        s.add(f64::NAN, 1);
        s.add(-3.0, 1);
        assert_eq!(
            s.points(),
            vec![RatePoint {
                t: 0.0,
                packets: 2,
                bytes: 2
            }]
        );
    }
}
