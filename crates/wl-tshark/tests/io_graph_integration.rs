//! `io_series` / `capture_properties` against the real fixtures (skipped without tshark).

use std::path::PathBuf;

use wl_model::{CaptureBackend, DeltaStat, IoSpec};
use wl_tshark::TsharkBackend;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/")
        .join(name)
}

fn spec(f: &str, d: Option<DeltaStat>) -> IoSpec {
    IoSpec {
        filter: f.into(),
        delta: d,
    }
}

#[test]
fn series_sum_to_the_capture_totals() {
    let Ok(b) = TsharkBackend::new() else { return };
    let file = fixture("sample.pcapng");
    let specs = [
        spec("", None),
        spec("tcp", Some(DeltaStat::Max)),
        spec("udp", None),
    ];
    let g = b.io_series(&file, &specs, 0.1).expect("io_series");
    assert_eq!(g.series.len(), 3);
    let total: u64 = g.series[0].packets.iter().sum();
    assert_eq!(total, 287);
    assert_eq!(g.series[1].delta.len(), g.series[1].packets.len());
    assert!(g.series[1].packets.iter().sum::<u64>() <= total);
    assert!(g.series[2].packets.iter().sum::<u64>() < total);
    assert!(g.duration > 1.5 && g.duration < 1.7);
    assert!(g.series[0].packets.len() >= 15);
}

#[test]
fn one_bad_filter_does_not_break_the_others() {
    let Ok(b) = TsharkBackend::new() else { return };
    let file = fixture("sample.pcapng");
    let specs = [
        spec("tcp", None),
        spec("not a filter &&&", None),
        spec("a,b", None),
    ];
    let g = b.io_series(&file, &specs, 1.0).expect("io_series");
    assert!(g.series[0].error.is_none() && !g.series[0].packets.is_empty());
    assert!(g.series[1].error.is_some());
    assert!(g.series[2].error.as_deref().unwrap().contains("commas"));
}

#[test]
fn properties_and_hash() {
    let Ok(b) = TsharkBackend::new() else { return };
    let file = fixture("sample.pcapng");
    let p = b.capture_properties(&file).expect("capinfos");
    assert_eq!(p.packets, 287);
    assert!(p.file_size > 1000 && p.duration > 1.0);
    assert!(!p.interfaces.is_empty());
    let h = b.file_sha256(&file).expect("sha");
    assert_eq!(h.len(), 64);
}
