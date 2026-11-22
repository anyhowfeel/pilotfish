//! Reads one capture file into the aggregates the diff compares.
use std::path::Path;
use std::thread;

use wl_model::{CaptureBackend, CaptureError, CaptureEvent};
use wl_stats::{CaptureData, StatsEngine};

/// Hosts and conversations kept per capture; far above the dashboard's 200 so the diff sees them all.
const TOP_N: usize = 100_000;

fn panicked() -> CaptureError {
    CaptureError::Other("a capture scan panicked".into())
}

fn stats(
    backend: &dyn CaptureBackend,
    file: &Path,
) -> Result<wl_model::StatsSnapshot, CaptureError> {
    let session = backend.start(wl_model::CaptureSource::File(file.to_path_buf()), None)?;
    let mut engine = StatsEngine::new();
    loop {
        match session.events.recv() {
            Ok(CaptureEvent::Rows(rows)) => engine.ingest_batch(&rows),
            Ok(CaptureEvent::Failed(e)) => return Err(e),
            Ok(CaptureEvent::Finished) | Err(_) => return Ok(engine.snapshot(TOP_N)),
        }
    }
}

pub fn scan(backend: &dyn CaptureBackend, file: &Path) -> Result<CaptureData, CaptureError> {
    thread::scope(|s| {
        let http = s.spawn(|| backend.http_exchanges(file));
        let tls = s.spawn(|| backend.tls_sessions(file));
        let dns = s.spawn(|| backend.dns_queries(file));
        let stats = stats(backend, file)?;
        Ok(CaptureData {
            stats: stats.into(),
            http: http.join().map_err(|_| panicked())??,
            tls: tls.join().map_err(|_| panicked())??,
            dns: dns.join().map_err(|_| panicked())??,
        })
    })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use wl_stats::{CaptureDiff, Presence};

    use super::scan;

    fn fixture(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures")
            .join(name)
    }

    #[test]
    fn two_fixture_captures_differ_and_one_never_differs_from_itself() {
        let Ok(backend) = wl_tshark::TsharkBackend::new() else {
            return;
        };
        let demo = scan(&backend, &fixture("demo.pcap")).unwrap();
        let behavior = scan(&backend, &fixture("behavior.pcap")).unwrap();
        assert!(demo.stats.total_packets > 0 && behavior.stats.total_packets > 0);
        assert!(CaptureDiff::compute(&demo, &demo).is_empty());
        let diff = CaptureDiff::compute(&demo, &behavior);
        assert!(!diff.is_empty());
        assert!(diff.hosts.iter().any(|r| r.presence() == Presence::Added));
        assert!(diff.hosts.iter().any(|r| r.presence() == Presence::Removed));
        assert_eq!(diff.before.packets, demo.stats.total_packets);
        assert_eq!(diff.after.packets, behavior.stats.total_packets);
    }
}
