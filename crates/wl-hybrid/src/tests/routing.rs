use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;

use wl_model::{CaptureBackend, CaptureError, CaptureSource, ClockZone, DecodeAs, IoSpec};

use super::doubles::{Rig, missing};

fn file() -> CaptureSource {
    CaptureSource::File(PathBuf::from("a.pcap"))
}

fn backing(r: Result<wl_model::Session, CaptureError>) -> String {
    r.map(|s| s.backing_file.display().to_string())
        .unwrap_or_else(|e| format!("error: {e}"))
}

fn rule() -> DecodeAs {
    DecodeAs {
        field: "tcp.port".into(),
        value: 8080,
        protocol: "http".into(),
    }
}

fn spec(f: &str) -> IoSpec {
    IoSpec {
        filter: f.into(),
        delta: None,
    }
}

#[test]
fn native_requests_never_build_the_deep_backend() {
    let r = Rig::working();
    let h = &r.hybrid;
    let p = Path::new("a.pcap");
    assert_eq!(backing(h.start(file(), None)), "native");
    assert_eq!(backing(h.start(file(), Some("  ".into()))), "native");
    assert_eq!(backing(h.start(file(), Some("tcp".into()))), "native");
    assert!(h.check_filter("tcp").is_ok());
    assert!(h.check_filter("").is_ok());
    assert!(h.capture_properties(p).is_ok());
    assert_eq!(h.file_sha256(p).unwrap(), "abc");
    assert!(h.io_series(p, &[spec("tcp"), spec("")], 1.0).is_ok());
    assert_eq!(r.builds(), 0);
    assert!(r.deep.calls().is_empty());
    assert_eq!(
        r.fast.calls(),
        [
            "start_file:-",
            "start_file:-",
            "start_file:tcp",
            "capture_properties:Local",
            "file_sha256",
            "io_series"
        ]
    );
}

#[test]
fn deep_requests_reach_the_deep_backend() {
    let r = Rig::working();
    let h = &r.hybrid;
    let p = Path::new("a.pcap");
    assert_eq!(backing(h.start(file(), Some("http".into()))), "deep");
    let live = CaptureSource::Live {
        interface: "eth0".into(),
        capture_filter: None,
    };
    assert_eq!(backing(h.start(live, None)), "deep");
    assert_eq!(
        h.check_filter("bad"),
        Err(CaptureError::BadFilter("bad".into()))
    );
    assert!(h.io_series(p, &[spec("tcp"), spec("dns")], 1.0).is_ok());
    assert!(h.frame_detail(p, 3).is_ok_and(|d| d.frame_no == 3));
    assert!(h.export(p, None, p).is_ok());
    assert_eq!(h.interfaces().unwrap().len(), 1);
    assert_eq!(
        r.deep.calls(),
        [
            "set_decode_as",
            "set_clock_zone",
            "start",
            "start",
            "check_filter",
            "io_series",
            "frame_detail",
            "export",
            "interfaces"
        ]
    );
    assert!(r.fast.calls().is_empty());
}

#[test]
fn io_series_falls_back_when_the_fast_path_declines() {
    let r = Rig::working();
    let p = Path::new("a.pcap");
    assert!(r.hybrid.io_series(p, &[spec("dns")], 1.0).is_ok());
    assert_eq!(r.fast.calls().len(), 0);
    assert_eq!(r.builds(), 1);
}

#[test]
fn the_deep_backend_is_built_once() {
    let r = Rig::working();
    for _ in 0..5 {
        assert!(r.hybrid.check_filter("http").is_ok());
    }
    assert_eq!(r.builds(), 1);
}

#[test]
fn concurrent_deep_requests_build_once() {
    let r = Arc::new(Rig::working());
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let r = r.clone();
            thread::spawn(move || {
                for _ in 0..20 {
                    assert!(r.hybrid.check_filter("http").is_ok());
                    assert!(r.hybrid.deep().is_ok());
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    assert_eq!(r.builds(), 1);
    assert_eq!(
        r.deep
            .calls()
            .iter()
            .filter(|c| *c == "check_filter")
            .count(),
        160
    );
}

#[test]
fn a_failed_build_is_cached_and_native_requests_still_work() {
    let r = Rig::broken();
    let h = &r.hybrid;
    let p = Path::new("a.pcap");
    for _ in 0..3 {
        assert_eq!(h.check_filter("http"), Err(missing()));
        assert_eq!(h.export(p, None, p), Err(missing()));
        assert_eq!(h.credentials(p).map(|_| ()), Err(missing()));
        assert_eq!(h.deep().map(|_| ()), Err(missing()));
        assert_eq!(h.check_capture_filter("eth0", "tcp"), Err(missing()));
        assert_eq!(
            h.start(file(), Some("http".into())).map(|_| ()),
            Err(missing())
        );
    }
    assert_eq!(r.builds(), 1);
    assert_eq!(backing(h.start(file(), Some("tcp".into()))), "native");
    assert!(h.check_filter("tcp").is_ok());
    assert!(h.capture_properties(p).is_ok());
    assert_eq!(r.builds(), 1);
}

#[test]
fn interfaces_are_empty_not_an_error_without_the_deep_backend() {
    let r = Rig::broken();
    assert_eq!(r.hybrid.interfaces(), Ok(Vec::new()));
}

#[test]
fn frame_detail_falls_back_to_the_native_summary() {
    let r = Rig::broken();
    let d = r.hybrid.frame_detail(Path::new("a.pcap"), 7).unwrap();
    assert_eq!(d.frame_no, 1007);
    assert_eq!(r.fast.calls(), ["native_frame_detail"]);
}

#[test]
fn decode_as_rules_reach_a_deep_backend_built_later() {
    let r = Rig::working();
    r.hybrid.set_decode_as(vec![rule()]);
    assert_eq!(r.builds(), 0);
    assert!(r.hybrid.check_filter("http").is_ok());
    assert_eq!(*r.deep.rules.lock().unwrap(), vec![rule()]);
}

#[test]
fn decode_as_rules_are_forwarded_to_an_existing_deep_backend() {
    let r = Rig::working();
    assert!(r.hybrid.check_filter("http").is_ok());
    r.hybrid.set_decode_as(vec![rule()]);
    assert_eq!(*r.deep.rules.lock().unwrap(), vec![rule()]);
    r.hybrid.set_decode_as(Vec::new());
    assert!(r.deep.rules.lock().unwrap().is_empty());
}

#[test]
fn an_active_rule_sends_files_to_the_deep_backend_until_cleared() {
    let r = Rig::working();
    r.hybrid.set_decode_as(vec![rule()]);
    assert_eq!(backing(r.hybrid.start(file(), None)), "deep");
    assert_eq!(backing(r.hybrid.start(file(), Some("tcp".into()))), "deep");
    r.hybrid.set_decode_as(Vec::new());
    assert_eq!(backing(r.hybrid.start(file(), None)), "native");
}

#[test]
fn a_rule_set_while_the_build_fails_still_routes_to_deep_with_its_error() {
    let r = Rig::broken();
    r.hybrid.set_decode_as(vec![rule()]);
    assert_eq!(r.hybrid.start(file(), None).map(|_| ()), Err(missing()));
}

#[test]
fn properties_are_read_in_local_time_until_the_zone_is_changed() {
    let r = Rig::working();
    let p = Path::new("a.pcap");
    r.hybrid.capture_properties(p).unwrap();
    r.hybrid.set_clock_zone(ClockZone::Utc);
    r.hybrid.capture_properties(p).unwrap();
    r.hybrid.set_clock_zone(ClockZone::Local);
    r.hybrid.capture_properties(p).unwrap();
    assert_eq!(
        r.fast.calls(),
        [
            "capture_properties:Local",
            "capture_properties:Utc",
            "capture_properties:Local"
        ]
    );
    assert_eq!(r.builds(), 0);
}

#[test]
fn the_zone_reaches_a_deep_backend_built_later() {
    let r = Rig::working();
    r.hybrid.set_clock_zone(ClockZone::Utc);
    assert_eq!(r.builds(), 0);
    assert!(r.hybrid.check_filter("http").is_ok());
    assert_eq!(*r.deep.zone.lock().unwrap(), Some(ClockZone::Utc));
}

#[test]
fn the_zone_is_forwarded_to_an_existing_deep_backend() {
    let r = Rig::working();
    assert!(r.hybrid.check_filter("http").is_ok());
    r.hybrid.set_clock_zone(ClockZone::Utc);
    assert_eq!(*r.deep.zone.lock().unwrap(), Some(ClockZone::Utc));
    r.hybrid.set_clock_zone(ClockZone::Local);
    assert_eq!(*r.deep.zone.lock().unwrap(), Some(ClockZone::Local));
}

#[test]
fn changing_the_zone_does_not_build_the_deep_backend() {
    let r = Rig::working();
    r.hybrid.set_clock_zone(ClockZone::Utc);
    assert_eq!(r.builds(), 0);
    assert!(r.deep.calls().is_empty());
}

#[test]
fn a_zone_set_while_the_build_fails_does_not_break_native_requests() {
    let r = Rig::broken();
    r.hybrid.set_clock_zone(ClockZone::Utc);
    assert!(r.hybrid.capture_properties(Path::new("a.pcap")).is_ok());
    assert_eq!(r.fast.calls(), ["capture_properties:Utc"]);
}
