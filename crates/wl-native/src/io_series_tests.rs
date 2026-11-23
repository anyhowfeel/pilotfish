use wl_model::{DeltaStat, IoGraph, IoSpec};

use super::*;
use crate::test_util::{
    Frame, PcapStyle, ng_epb, ng_idb, ng_shb, pcap_bytes, pcapng_bytes, sample_frames,
};

pub(super) fn frame(epoch: f64, len: usize) -> Frame {
    Frame::new(epoch, vec![0; len])
}

pub(super) fn all(delta: Option<DeltaStat>) -> IoSpec {
    IoSpec {
        filter: String::new(),
        delta,
    }
}

pub(super) fn run(
    bytes: Vec<u8>,
    specs: &[IoSpec],
    interval: f64,
) -> Result<IoGraph, CaptureError> {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("x.cap");
    std::fs::write(&path, bytes).expect("write");
    compute(&path, specs, interval).expect("empty filters are always native")
}

/// Frames of 60 bytes at `times`, in file order.
pub(super) fn at(times: &[f64]) -> Vec<u8> {
    let frames: Vec<Frame> = times.iter().map(|t| frame(*t, 60)).collect();
    pcap_bytes(&frames, PcapStyle::default())
}

fn counts(times: &[f64], interval: f64) -> Vec<u64> {
    run(at(times), &[all(None)], interval)
        .expect("graph")
        .series[0]
        .packets
        .clone()
}

#[test]
fn an_empty_capture_has_one_empty_bucket() {
    let g = run(at(&[]), &[all(Some(DeltaStat::Max))], 1.0).expect("graph");
    assert_eq!((g.interval, g.duration), (1.0, 0.0));
    let s = &g.series[0];
    assert_eq!(
        (&s.packets[..], &s.bytes[..], &s.delta[..]),
        (&[0][..], &[0][..], &[0.0][..])
    );
    assert_eq!(s.error, None);
}

#[test]
fn one_packet_fills_the_only_bucket() {
    let g = run(at(&[100.0]), &[all(Some(DeltaStat::Min))], 1.0).expect("graph");
    assert_eq!(g.duration, 0.0);
    let s = &g.series[0];
    assert_eq!(
        (&s.packets[..], &s.bytes[..], &s.delta[..]),
        (&[1][..], &[60][..], &[0.0][..])
    );
}

#[test]
fn buckets_start_at_the_first_packet_and_cover_the_duration() {
    let g = run(at(&[100.0, 100.5, 101.0, 102.0, 102.2]), &[all(None)], 1.0).expect("graph");
    assert_eq!(g.series[0].packets, vec![2, 1, 2]);
    assert_eq!(g.series[0].bytes, vec![120, 60, 120]);
    assert!((g.duration - 2.2).abs() < 1e-9);
}

#[test]
fn a_packet_at_the_exact_end_of_an_aligned_capture_is_dropped_like_tshark() {
    assert_eq!(counts(&[100.0, 100.5, 101.0, 102.0], 1.0), vec![2, 1]);
    assert_eq!(counts(&[100.0, 100.5, 101.0, 102.0], 0.5), vec![1, 1, 1, 0]);
}

#[test]
fn a_packet_on_an_interval_edge_starts_the_next_bucket() {
    let t0 = 1_700_000_000.123_456;
    assert_eq!(
        counts(&[t0, t0 + 1.0, t0 + 2.0, t0 + 2.5], 1.0),
        vec![1, 1, 2]
    );
    assert_eq!(
        counts(&[t0, t0 + 0.001, t0 + 0.0019, t0 + 0.002], 0.001),
        vec![1, 2]
    );
}

#[test]
fn nanosecond_files_are_bucketed_too() {
    let style = PcapStyle {
        nanos: true,
        ..PcapStyle::default()
    };
    let frames = [
        frame(1_700_000_000.0, 60),
        frame(1_700_000_001.0, 60),
        frame(1_700_000_001.5, 60),
    ];
    let g = run(pcap_bytes(&frames, style), &[all(None)], 1.0).expect("graph");
    assert_eq!(g.series[0].packets, vec![1, 2]);
}

#[test]
fn nanosecond_stamps_round_to_the_nearest_microsecond_like_tshark() {
    let t = 1_700_000_000_000_000_000_u64;
    let mut bytes = ng_shb(false);
    bytes.extend(ng_idb(false, 1, 0, Some(9)));
    for offset in [0, 499, 999_999_499, 999_999_500, 2_500_000_000] {
        bytes.extend(ng_epb(false, 0, t + offset, &[0; 60], 60));
    }
    let g = run(bytes, &[all(Some(DeltaStat::Min))], 1.0).expect("graph");
    assert_eq!(g.series[0].packets, vec![3, 1, 1]);
    assert_eq!(g.series[0].delta[0], 4.99e-7);
    assert_eq!(g.series[0].delta[1], 1e-9);
}

#[test]
fn every_interval_keeps_every_packet_and_has_ceil_of_duration_over_interval_buckets() {
    let times: Vec<f64> = [0.0, 0.0004, 0.9, 1.2345, 1.9999, 2.5, 2.9995]
        .iter()
        .map(|t| 1_700_000_000.0 + t)
        .collect();
    for interval in [0.001, 0.01, 0.1, 0.5, 1.0, 2.5, 10.0, 60.0] {
        let g = run(at(&times), &[all(None)], interval).expect("graph");
        let s = &g.series[0];
        assert_eq!(s.packets.iter().sum::<u64>(), 7, "interval {interval}");
        assert_eq!(s.bytes.iter().sum::<u64>(), 7 * 60);
        let rows = ((2.9995 / interval).ceil() as usize).max(1);
        assert_eq!(s.packets.len(), rows, "interval {interval}");
        assert_eq!(g.interval, interval);
    }
}

#[test]
fn the_interval_is_clamped_like_the_tshark_path() {
    let at_one = |i| run(at(&[1.0]), &[all(None)], i).expect("graph").interval;
    assert_eq!(at_one(0.0001), 0.001);
    assert_eq!(at_one(-5.0), 0.001);
    assert_eq!(at_one(f64::NAN), 1.0);
    assert_eq!(at_one(f64::INFINITY), 1.0);
}

#[test]
fn a_packet_older_than_the_one_before_stays_in_the_current_bucket() {
    let times = [100.0, 100.5, 99.0, 102.5, 101.0, 100.2, 101.5, 102.9];
    assert_eq!(counts(&times, 1.0), vec![3, 0, 5]);
    assert_eq!(counts(&times, 0.5), vec![1, 2, 0, 0, 0, 5]);
}

#[test]
fn delta_statistics_use_the_previous_packet_of_the_file() {
    let times = [0.0, 0.1, 0.35, 1.5, 1.6].map(|t| 1000.0 + t);
    let specs = [
        all(Some(DeltaStat::Max)),
        all(Some(DeltaStat::Min)),
        all(None),
    ];
    let g = run(at(&times), &specs, 1.0).expect("graph");
    let close = |got: &[f64], want: &[f64]| {
        assert_eq!(got.len(), want.len());
        assert!(
            got.iter().zip(want).all(|(a, b)| (a - b).abs() < 1e-9),
            "{got:?}"
        );
    };
    close(&g.series[0].delta, &[0.25, 1.15]);
    close(&g.series[1].delta, &[0.1, 0.1]);
    assert!(g.series[2].delta.is_empty());
    assert_eq!(g.series[0].packets, g.series[2].packets);
}

#[test]
fn a_bucket_without_deltas_reports_zero() {
    let g = run(at(&[10.0, 10.2, 13.5]), &[all(Some(DeltaStat::Max))], 1.0).expect("graph");
    assert_eq!(g.series[0].packets, vec![2, 0, 0, 1]);
    assert!((g.series[0].delta[0] - 0.2).abs() < 1e-9);
    assert_eq!(&g.series[0].delta[1..3], &[0.0, 0.0]);
    assert!((g.series[0].delta[3] - 3.3).abs() < 1e-9);
}

#[test]
fn bytes_are_the_length_on_the_wire() {
    let mut cut = frame(100.0, 40);
    cut.orig_len = Some(1500);
    let bytes = pcap_bytes(&[cut, frame(100.5, 60)], PcapStyle::default());
    assert_eq!(
        run(bytes, &[all(None)], 1.0).expect("graph").series[0].bytes,
        vec![1560]
    );
}

#[test]
fn pcap_and_pcapng_give_the_same_graph() {
    let frames = sample_frames();
    let specs = [all(Some(DeltaStat::Max))];
    let a = run(pcap_bytes(&frames, PcapStyle::default()), &specs, 0.3).expect("pcap");
    let b = run(pcapng_bytes(&frames), &specs, 0.3).expect("pcapng");
    assert_eq!(a, b);
    assert_eq!(a.series[0].packets.iter().sum::<u64>(), frames.len() as u64);
}

#[test]
fn several_series_come_out_of_one_pass_in_request_order() {
    let specs = [
        all(Some(DeltaStat::Min)),
        all(None),
        all(Some(DeltaStat::Max)),
    ];
    let g = run(at(&[1.0, 1.4, 3.5]), &specs, 1.0).expect("graph");
    assert_eq!(g.series.len(), 3);
    assert_eq!(
        (
            g.series[0].delta.len(),
            g.series[1].delta.len(),
            g.series[2].delta.len()
        ),
        (3, 0, 3)
    );
    assert!(g.series.iter().all(|s| s.packets == vec![2, 0, 1]));
}
