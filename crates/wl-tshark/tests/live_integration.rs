//! Live capture lifecycle on `lo` (needs tshark + dumpcap and capture rights; skipped otherwise).
mod common;

use std::time::{Duration, Instant};

use common::{backend, collect, send_udp};
use wl_model::{CaptureBackend, CaptureError, CaptureEvent, CaptureSource};

fn cmdline_count(needle: &str) -> usize {
    let me = std::process::id().to_string();
    std::fs::read_dir("/proc")
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy() != me)
        .filter_map(|e| std::fs::read(e.path().join("cmdline")).ok())
        .filter(|c| {
            let text = String::from_utf8_lossy(c);
            let a0 = text.split('\0').next().unwrap_or("");
            (a0.ends_with("tshark") || a0.ends_with("dumpcap")) && text.contains(needle)
        })
        .count()
}

#[test]
fn live_capture_and_drop_cleanup() {
    let Some(b) = backend() else { return };
    let mk = |f: &str| CaptureSource::Live {
        interface: "lo".into(),
        capture_filter: Some(f.into()),
    };
    let mut s = match b.start(mk("udp port 40003"), Some("udp.port == 40003".into())) {
        Ok(s) => s,
        Err(CaptureError::Permission(_)) => return,
        Err(e) => panic!("{e:?}"),
    };
    assert!(cmdline_count("40003") >= 2);
    std::thread::sleep(Duration::from_millis(600));
    send_udp(40003, 10);
    let (mut got, end) = (0, Instant::now() + Duration::from_secs(10));
    while got < 10 && Instant::now() < end {
        if let Ok(CaptureEvent::Rows(r)) = s.events.recv_timeout(Duration::from_millis(200)) {
            got += r.len();
        }
    }
    assert_eq!(got, 10);
    (s.stop)();
    assert_eq!(cmdline_count("40003"), 0);
    assert!(!b.frame_detail(&s.backing_file, 1).unwrap().bytes.is_empty());
    assert!(collect(&s).1.is_none());

    if let Ok(s2) = b.start(mk("udp port 40004"), None) {
        drop(s2);
        assert_eq!(cmdline_count("40004"), 0);
    }
    assert!(matches!(
        b.start(mk("foo bar ("), None),
        Err(CaptureError::BadFilter(_))
    ));
}

#[test]
fn live_options_ring_save_and_auto_stop() {
    let Some(b) = backend() else { return };
    let dir = tempfile::tempdir().expect("tmp");
    let mut o = wl_model::CaptureOptions::single("lo", Some("udp port 40005"));
    o.stop.packets = 5;
    o.ring.enabled = true;
    o.ring.files = 3;
    o.save_to = dir.path().join("ring/cap.pcapng").display().to_string();
    let s = match b.start(CaptureSource::Capture(o), None) {
        Ok(s) => s,
        Err(CaptureError::Permission(_)) => return,
        Err(e) => panic!("{e:?}"),
    };
    std::thread::sleep(Duration::from_millis(600));
    send_udp(40005, 5);
    // -c 5 ends the stream by itself: the session finishes without stop().
    let (rows, err) = collect(&s);
    assert!(err.is_none(), "{err:?}");
    assert_eq!(rows.len(), 5);
    let files = std::fs::read_dir(dir.path().join("ring")).map_or(0, Iterator::count);
    assert!(files >= 1, "ring recorder wrote nothing");
}

#[test]
fn capture_filter_check_names_the_error() {
    let Some(b) = backend() else { return };
    assert!(b.check_capture_filter("lo", "port 80").is_ok());
    assert!(matches!(
        b.check_capture_filter("lo", "port ("),
        Err(CaptureError::BadFilter(_))
    ));
}
