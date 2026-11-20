//! Capture clock and packet-rate estimator used by `Controller`.
use std::time::Instant;

use crate::state::{RunState, StatusInfo};

pub struct CaptureClock {
    started: Instant,
    last_rel: f64,
    rate_mark: (Instant, u64),
}

impl CaptureClock {
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            started: now,
            last_rel: 0.0,
            rate_mark: (now, 0),
        }
    }

    pub fn reset(&mut self) {
        let now = Instant::now();
        self.started = now;
        self.last_rel = 0.0;
        self.rate_mark = (now, 0);
    }

    pub fn observe_rel(&mut self, rel: f64) {
        self.last_rel = rel;
    }

    pub fn update(&mut self, status: &mut StatusInfo, is_live: bool) {
        let running = status.state == RunState::Running;
        status.elapsed = if running && is_live {
            self.started.elapsed().as_secs_f64()
        } else {
            self.last_rel
        };
        let dt = self.rate_mark.0.elapsed().as_secs_f64();
        if dt >= 0.5 {
            let n = status.packets.saturating_sub(self.rate_mark.1);
            status.rate_pps = if running { n as f64 / dt } else { 0.0 };
            self.rate_mark = (Instant::now(), status.packets);
        }
    }
}
