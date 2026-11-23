//! The controller without Wireshark: tshark-only work stays quiet or says what is needed.
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use wl_hybrid::{HybridBackend, NativeBackend};
use wl_model::{CaptureError, CaptureSource};

use super::Controller;

fn controller() -> Controller {
    let backend = HybridBackend::new(NativeBackend::new(), || {
        Err(CaptureError::ToolMissing("tshark".into()))
    });
    Controller::new(Arc::new(backend))
}

fn sample() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/sample.pcapng")
}

fn settle(c: &mut Controller) {
    let t = Instant::now();
    while t.elapsed() < Duration::from_secs(10) {
        c.poll();
        if !c.is_busy() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn opened() -> Controller {
    let mut c = controller();
    c.start(CaptureSource::File(sample()), None);
    settle(&mut c);
    c
}

#[test]
fn the_native_file_opens_without_an_error() {
    let c = opened();
    assert!(c.error().is_none());
    assert!(c.status().packets > 0);
}

#[test]
fn a_web_scan_without_wireshark_leaves_no_banner() {
    let mut c = opened();
    c.set_web_active(true);
    c.request_web();
    settle(&mut c);
    assert!(c.poll_web().is_none());
    assert!(c.error().is_none());
}

#[test]
fn exporting_without_wireshark_is_a_notice_not_an_error() {
    let mut c = opened();
    c.export(
        None,
        std::env::temp_dir().join("pilotfish-missing-export.pcapng"),
    );
    let t = Instant::now();
    while c.notice().is_none() && t.elapsed() < Duration::from_secs(10) {
        c.poll();
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        c.notice(),
        Some("Exporting packets needs Wireshark. Install Wireshark and restart pilotfish.")
    );
    assert!(c.error().is_none());
}

#[test]
fn a_filter_wireshark_must_evaluate_says_so() {
    let mut c = controller();
    c.start(
        CaptureSource::File(sample()),
        Some("http.request.method == \"GET\"".into()),
    );
    let text = c.error().map(ToString::to_string).unwrap_or_default();
    assert_eq!(
        text,
        "This display filter needs Wireshark. Install Wireshark and restart pilotfish."
    );
}

#[test]
fn a_live_capture_without_wireshark_says_so() {
    let mut c = controller();
    c.start(
        CaptureSource::Live {
            interface: "lo".into(),
            capture_filter: None,
        },
        None,
    );
    let text = c.error().map(ToString::to_string).unwrap_or_default();
    assert!(text.starts_with("Live capture needs Wireshark."), "{text}");
}
