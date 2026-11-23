use std::path::Path;

use wl_model::{DeltaStat, IoSpec};

use super::clock::MAX_BUCKETS;
use super::compute;
use super::tests::{all, at, run};
use crate::test_util::{Frame, PcapStyle, SYN, tcp4, udp4, write_pcap};

#[test]
fn a_capture_spanning_years_at_one_millisecond_is_refused_with_a_clear_error() {
    let years = 3.0 * 365.0 * 86_400.0;
    let e = run(at(&[1_000.0, 1_000.0 + years]), &[all(None)], 0.001).expect_err("too many");
    let text = e.to_string();
    assert!(
        text.contains("0.001") && text.contains("longer interval"),
        "{text}"
    );
    let ok = run(at(&[1_000.0, 1_000.0 + years]), &[all(None)], 3600.0).expect("graph");
    assert_eq!(ok.series[0].packets.len(), 26_280);
}

#[test]
fn exactly_the_largest_bucket_count_is_still_served() {
    let last = 1_000.0 + 1_000.0;
    let g = run(at(&[1_000.0, last]), &[all(None)], 0.001).expect("graph");
    assert_eq!(g.series[0].packets.len(), MAX_BUCKETS);
    assert_eq!(g.series[0].packets.iter().sum::<u64>(), 1);
    assert!(run(at(&[1_000.0, 2_000.002]), &[all(None)], 0.001).is_err());
}

#[test]
fn unreadable_files_are_errors() {
    let dir = tempfile::tempdir().expect("tempdir");
    let none = dir.path().join("none.pcap");
    assert!(compute(&none, &[all(None)], 1.0).expect("native").is_err());
    let junk = dir.path().join("junk.pcap");
    std::fs::write(&junk, b"not a capture file, just text").expect("write");
    assert!(compute(&junk, &[all(None)], 1.0).expect("native").is_err());
    let mut bytes = at(&[1.0, 2.0, 3.0]);
    bytes.truncate(bytes.len() - 5);
    let cut = dir.path().join("cut.pcap");
    std::fs::write(&cut, bytes).expect("write");
    assert!(compute(&cut, &[all(None)], 1.0).expect("native").is_err());
}

fn mixed_file(dir: &Path) -> std::path::PathBuf {
    let a = (std::net::Ipv4Addr::new(10, 0, 0, 1), 5000);
    let b = (std::net::Ipv4Addr::new(10, 0, 0, 2), 53);
    let frames = vec![
        Frame::new(100.0, udp4(a, b, b"x")),
        Frame::new(100.4, tcp4(a, b, SYN, 1, 0, &[])),
        Frame::new(101.2, udp4(a, b, b"y")),
    ];
    let path = dir.join("mixed.pcap");
    write_pcap(&path, &frames, PcapStyle::default());
    path
}

fn spec(filter: &str, delta: Option<DeltaStat>) -> IoSpec {
    IoSpec {
        filter: filter.into(),
        delta,
    }
}

#[test]
fn a_filter_keeps_the_bucket_axis_of_the_whole_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = mixed_file(dir.path());
    let g = compute(
        &path,
        &[spec("udp", Some(DeltaStat::Max)), spec("tcp", None)],
        1.0,
    )
    .expect("supported")
    .expect("graph");
    assert_eq!(g.series[0].packets, vec![1, 1]);
    assert_eq!(g.series[1].packets, vec![1, 0]);
    assert!((g.series[0].delta[1] - 0.8).abs() < 1e-9);
}

#[test]
fn an_unsupported_filter_is_none_before_the_file_is_opened() {
    let missing = Path::new("/nonexistent/never.pcap");
    let specs = [spec("", None), spec("frame contains \"x\" && !!!(", None)];
    assert!(compute(missing, &specs, 1.0).is_none());
}
