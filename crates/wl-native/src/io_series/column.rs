//! One graph series being filled: counts, bytes and the optional time-delta statistic per bucket.

use wl_model::{DeltaStat, IoSeries, IoSpec};

use crate::filter::Filter;

pub struct Column {
    filter: Option<Filter>,
    stat: Option<DeltaStat>,
    /// Bucket of the last packet this series took. tshark never moves back from it, so a packet
    /// older than the one before it counts in the same bucket.
    current: usize,
    packets: Vec<u64>,
    bytes: Vec<u64>,
    /// NaN where no packet has contributed yet.
    delta: Vec<f64>,
}

impl Column {
    pub fn new(spec: &IoSpec, filter: Option<Filter>) -> Self {
        Self {
            filter,
            stat: spec.delta,
            current: 0,
            packets: Vec::new(),
            bytes: Vec::new(),
            delta: Vec::new(),
        }
    }

    pub fn filter(&self) -> Option<&Filter> {
        self.filter.as_ref()
    }

    pub fn add(&mut self, index: i64, wire_len: u32, delta: Option<f64>) {
        let at = usize::try_from(index).unwrap_or(0).max(self.current);
        self.current = at;
        self.grow(at + 1);
        self.packets[at] += 1;
        self.bytes[at] += u64::from(wire_len);
        let (Some(stat), Some(d)) = (self.stat, delta) else {
            return;
        };
        let slot = &mut self.delta[at];
        let wins = |old: f64| match stat {
            DeltaStat::Max => d > old,
            DeltaStat::Min => d < old,
        };
        if slot.is_nan() || wins(*slot) {
            *slot = d;
        }
    }

    fn grow(&mut self, len: usize) {
        if self.packets.len() < len {
            self.packets.resize(len, 0);
            self.bytes.resize(len, 0);
            if self.stat.is_some() {
                self.delta.resize(len, f64::NAN);
            }
        }
    }

    /// The series cut or padded to `buckets`. A packet beyond the last bucket is dropped.
    pub fn finish(mut self, buckets: usize) -> IoSeries {
        self.packets.resize(buckets, 0);
        self.bytes.resize(buckets, 0);
        if self.stat.is_some() {
            self.delta.resize(buckets, f64::NAN);
        }
        IoSeries {
            packets: self.packets,
            bytes: self.bytes,
            delta: self
                .delta
                .into_iter()
                .map(|d| if d.is_nan() { 0.0 } else { d })
                .collect(),
            error: None,
        }
    }
}
