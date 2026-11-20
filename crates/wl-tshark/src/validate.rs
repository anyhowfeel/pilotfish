//! Display filter validation without capturing anything.

use std::collections::VecDeque;
use std::path::Path;
use std::sync::Mutex;

use wl_model::CaptureError;

use crate::capture_args::check_args;
use crate::error::{from_display_filter_failure, from_dumpcap};
use crate::process::{Tools, run};

/// Minimal valid (empty) classic pcap file header, little endian, Ethernet.
pub const EMPTY_PCAP: [u8; 24] = [
    0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0, 0, 0,
];

/// Filters tshark already accepted. The UI validates while typing and again on apply; this makes
/// the second (synchronous, ~100 ms spawn) check free. Bounded; a tshark upgrade needs a restart anyway.
static ACCEPTED: Mutex<VecDeque<String>> = Mutex::new(VecDeque::new());
const ACCEPTED_CAP: usize = 64;

fn was_accepted(filter: &str) -> bool {
    let q = ACCEPTED.lock().unwrap_or_else(|e| e.into_inner());
    q.iter().any(|f| f == filter)
}

fn remember(filter: &str) {
    let mut q = ACCEPTED.lock().unwrap_or_else(|e| e.into_inner());
    if q.len() >= ACCEPTED_CAP {
        q.pop_front();
    }
    q.push_back(filter.to_string());
}

/// tshark parses `-Y` before reading packets; running it on an empty pcap is the cheapest check
/// (`/dev/null` is rejected by tshark as a special file).
pub fn display_filter(tools: &Tools, empty_pcap: &Path, filter: &str) -> Result<(), CaptureError> {
    if filter.trim().is_empty() || was_accepted(filter) {
        return Ok(());
    }
    let out = run(
        &tools.tshark,
        [
            "-r".as_ref(),
            empty_pcap.as_os_str(),
            "-Y".as_ref(),
            std::ffi::OsStr::new(filter),
        ],
    )?;
    if out.status.success() {
        remember(filter);
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&out.stderr);
        Err(from_display_filter_failure(&stderr, out.status.code()).into_bad_filter())
    }
}

/// Compiles a capture (BPF) filter for `interface` with `dumpcap -d`; nothing is captured.
pub fn capture_filter(tools: &Tools, interface: &str, filter: &str) -> Result<(), CaptureError> {
    if filter.trim().is_empty() {
        return Ok(());
    }
    let out = run(&tools.dumpcap, check_args(interface, filter.trim()))?;
    // dumpcap -d reports a rejected filter on stderr but still exits 0.
    let stderr = String::from_utf8_lossy(&out.stderr);
    if out.status.success() && !stderr.to_lowercase().contains("invalid capture filter") {
        Ok(())
    } else {
        Err(from_dumpcap(&stderr))
    }
}

trait IntoBadFilter {
    fn into_bad_filter(self) -> CaptureError;
}

impl IntoBadFilter for CaptureError {
    /// Anything tshark rejects while only validating a filter is a filter problem.
    fn into_bad_filter(self) -> CaptureError {
        match self {
            CaptureError::Other(m) => CaptureError::BadFilter(m),
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn dead_tools() -> Tools {
        Tools {
            tshark: PathBuf::from("/nonexistent/tshark"),
            dumpcap: PathBuf::from("/nonexistent/dumpcap"),
            editcap: None,
            mergecap: None,
        }
    }

    #[test]
    fn accepted_filter_skips_the_spawn_and_cache_is_bounded() {
        let empty = Path::new("/nonexistent/empty.pcap");
        assert!(display_filter(&dead_tools(), empty, "wl.unseen.filter").is_err());
        remember("wl.cached.filter");
        assert!(display_filter(&dead_tools(), empty, "wl.cached.filter").is_ok());
        for i in 0..(ACCEPTED_CAP * 2) {
            remember(&format!("wl.flood == {i}"));
        }
        let len = ACCEPTED.lock().map(|q| q.len()).unwrap_or(0);
        assert!(len <= ACCEPTED_CAP);
    }
}
