//! Tracks incremental `StatsEngine` snapshots (throttled to 4 Hz), elapsed clock, and packet rate.
use std::sync::Arc;
use std::time::{Duration, Instant};

use wl_model::{PacketRow, StatsSnapshot};
use wl_stats::StatsEngine;

use crate::clock::CaptureClock;
use crate::state::StatusInfo;

const DEFAULT_SNAPSHOT_EVERY: Duration = Duration::from_millis(250);
const TOP_N: usize = 200;

pub struct Metrics {
    /// Minimum time between two statistics snapshots (Settings > Performance).
    every: Duration,
    stats: StatsEngine,
    snapshot: Arc<StatsSnapshot>,
    dirty: bool,
    last_snapshot: Instant,
    clock: CaptureClock,
}

impl Metrics {
    /// Snapshot rate in Hz (clamped 1..=30).
    pub fn set_hz(&mut self, hz: u32) {
        self.every = Duration::from_millis(1000 / u64::from(hz.clamp(1, 30)));
    }

    pub fn new() -> Self {
        Self {
            every: DEFAULT_SNAPSHOT_EVERY,
            stats: StatsEngine::new(),
            snapshot: Arc::new(StatsSnapshot::default()),
            dirty: false,
            last_snapshot: Instant::now(),
            clock: CaptureClock::new(),
        }
    }

    pub fn snapshot(&self) -> &Arc<StatsSnapshot> {
        &self.snapshot
    }

    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    pub fn reset(&mut self) {
        self.stats.reset();
        self.snapshot = Arc::new(StatsSnapshot::default());
        self.dirty = false;
        self.clock.reset();
    }

    pub fn ingest(&mut self, rows: &[PacketRow], status: &mut StatusInfo) {
        self.stats.ingest_batch(rows);
        status.packets += rows.len() as u64;
        if let Some(last) = rows.last() {
            self.clock.observe_rel(last.rel);
        }
        self.dirty = true;
    }

    pub fn tick(&mut self, status: &mut StatusInfo, is_live: bool, done: bool) -> bool {
        self.clock.update(status, is_live);
        if self.dirty && (done || self.last_snapshot.elapsed() >= self.every) {
            self.snapshot = Arc::new(self.stats.snapshot(TOP_N));
            self.last_snapshot = Instant::now();
            self.dirty = false;
            return true;
        }
        false
    }
}
