use std::time::Duration;

use crossbeam_channel::bounded;
use wl_model::{CaptureError, CaptureEvent};

use super::test_support::*;
use super::worker::send;
use crate::test_util::{PcapStyle, numbered_frames, pcap_bytes, sample_frames};
use std::sync::atomic::{AtomicBool, Ordering};

#[test]
fn a_truncated_file_gives_its_good_rows_then_failed() {
    let _g = serial();
    let dir = tempfile::tempdir().expect("dir");
    let mut bytes = pcap_bytes(&numbered_frames(10), PcapStyle::default());
    bytes.truncate(bytes.len() - 10);
    let path = dir.path().join("cut.pcap");
    std::fs::write(&path, bytes).expect("write");
    let got = run(&path).expect("start");
    assert_eq!(got.rows().len(), 9);
    assert!(matches!(
        &got.terminals[..],
        [CaptureEvent::Failed(CaptureError::Other(m))] if m.contains("damaged")
    ));
    assert_eq!(got.after_terminal, 0);
}

#[test]
fn rows_before_a_failure_are_sent_before_it() {
    let _g = serial();
    let dir = tempfile::tempdir().expect("dir");
    let mut bytes = pcap_bytes(&sample_frames(), PcapStyle::default());
    bytes.truncate(bytes.len() - 1);
    let path = dir.path().join("cut.pcap");
    std::fs::write(&path, bytes).expect("write");
    let session = started(&path);
    let first = session
        .events
        .recv_timeout(Duration::from_secs(5))
        .expect("event");
    assert!(matches!(first, CaptureEvent::Rows(r) if r.len() == sample_frames().len() - 1));
    let second = session
        .events
        .recv_timeout(Duration::from_secs(5))
        .expect("event");
    assert!(matches!(second, CaptureEvent::Failed(_)));
}

#[test]
fn a_header_only_truncation_fails_at_start_or_with_no_rows() {
    let _g = serial();
    let dir = tempfile::tempdir().expect("dir");
    let mut bytes = pcap_bytes(&sample_frames(), PcapStyle::default());
    bytes.truncate(30);
    let path = dir.path().join("cut.pcap");
    std::fs::write(&path, bytes).expect("write");
    match run(&path) {
        Err(_) => {}
        Ok(got) => {
            assert!(got.rows().is_empty());
            assert!(matches!(got.terminals[..], [CaptureEvent::Failed(_)]));
        }
    }
}

#[test]
fn send_gives_up_when_stopped_while_the_channel_is_full() {
    let (tx, _rx) = bounded::<CaptureEvent>(1);
    let stop = AtomicBool::new(false);
    assert!(send(&tx, &stop, CaptureEvent::Finished));
    std::thread::scope(|s| {
        let h = s.spawn(|| send(&tx, &stop, CaptureEvent::Finished));
        std::thread::sleep(Duration::from_millis(30));
        stop.store(true, Ordering::SeqCst);
        assert!(!h.join().expect("join"));
    });
}

#[test]
fn send_gives_up_when_the_receiver_is_gone() {
    let (tx, rx) = bounded::<CaptureEvent>(1);
    drop(rx);
    assert!(!send(&tx, &AtomicBool::new(false), CaptureEvent::Finished));
}
