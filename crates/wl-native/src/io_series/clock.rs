//! Where a packet falls on the time axis of `tshark -z io,stat`: bucket index, the distance to
//! the packet before it, and how many buckets the table has.

use wl_model::CaptureError;

use crate::reader::Stamp;

/// Buckets one series may have. A year-long capture at 1 ms would need 31 billion; tshark would
/// print them all, the graph could not show them.
pub const MAX_BUCKETS: usize = 1_000_000;

const NANOS: f64 = 1e9;

pub struct Tick {
    /// Floor of the time since the first packet over the interval; negative for a packet that
    /// is older than the first.
    pub index: i64,
    /// Seconds since the previous packet in the file; `None` for the first.
    pub delta: Option<f64>,
}

pub struct Clock {
    interval_us: i64,
    first: Option<Stamp>,
    previous: Option<i64>,
    longest: i64,
}

impl Clock {
    pub fn new(interval: f64) -> Self {
        Self {
            interval_us: (interval * 1e6).round().max(1.0) as i64,
            first: None,
            previous: None,
            longest: 0,
        }
    }

    /// Places the packet stamped `at`. The stamps are exact; the f64 epoch of a packet is good
    /// to 0.24 us only, which would move packets next to an interval edge. tshark rounds the
    /// time since the first packet to the nearest microsecond before it picks the bucket.
    pub fn tick(&mut self, at: &Stamp) -> Result<Tick, CaptureError> {
        let first = self.first.get_or_insert(*at);
        let secs = i128::from(at.secs) - i128::from(first.secs);
        let nanos = i128::from(at.nanos) - i128::from(first.nanos);
        let rel_ns = i64::try_from(secs * 1_000_000_000 + nanos).unwrap_or(i64::MAX);
        let index = micros(rel_ns).div_euclid(self.interval_us);
        if index > MAX_BUCKETS as i64 {
            return Err(too_many(self.interval_us));
        }
        let delta = self.previous.map(|p| (rel_ns - p) as f64 / NANOS);
        self.previous = Some(rel_ns);
        self.longest = self.longest.max(rel_ns);
        Ok(Tick { index, delta })
    }

    /// Capture duration in seconds: the largest distance from the first packet.
    pub fn duration(&self) -> f64 {
        self.longest as f64 / NANOS
    }

    /// Rows of the table: the duration over the interval, rounded up, and at least one. A packet
    /// at exactly the end of an interval-aligned capture would need one more and is not counted,
    /// as in tshark.
    pub fn buckets(&self) -> Result<usize, CaptureError> {
        let rows = (micros(self.longest) + self.interval_us - 1) / self.interval_us;
        if rows > MAX_BUCKETS as i64 {
            return Err(too_many(self.interval_us));
        }
        Ok(rows.max(1) as usize)
    }
}

fn micros(nanos: i64) -> i64 {
    nanos.saturating_add(500).div_euclid(1000)
}

fn too_many(interval_us: i64) -> CaptureError {
    CaptureError::Other(format!(
        "an interval of {} s gives more than {MAX_BUCKETS} points for this capture; use a longer interval",
        interval_us as f64 / 1e6
    ))
}
