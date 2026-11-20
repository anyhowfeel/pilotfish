//! Builds the end-of-stream callback shared by live and file sessions.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use wl_model::CaptureError;

use crate::error::from_display_filter_failure;
use crate::process::{Proc, StderrTap};
use crate::pump::Finish;

/// Error reported by the upstream producer (dumpcap), if it failed on its own.
pub type ProducerError = Arc<Mutex<Option<CaptureError>>>;

pub fn tshark_finish(tshark: Proc, tap: StderrTap, producer_err: Option<ProducerError>) -> Finish {
    Box::new(move |stopped| {
        let status = tshark.wait_exit(Duration::from_secs(2));
        if status.is_none() {
            tshark.kill();
        }
        let stderr = tap.finish();
        if stopped {
            return None;
        }
        if let Some(e) = producer_err.and_then(|p| p.lock().ok().and_then(|mut g| g.take())) {
            return Some(e);
        }
        match status {
            Some(s) if !s.success() => Some(from_display_filter_failure(&stderr, s.code())),
            _ => None,
        }
    })
}
