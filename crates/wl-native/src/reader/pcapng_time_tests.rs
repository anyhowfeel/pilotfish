use crate::test_util::{ng_epb, ng_idb, ng_shb};

use super::super::ReadError;
use super::tests::{cat, read};

const ETH: u16 = 1;

fn one_packet_epoch(tsresol: Option<u8>, ticks: u64, be: bool) -> f64 {
    let bytes = cat(&[
        ng_shb(be),
        ng_idb(be, ETH, 0, tsresol),
        ng_epb(be, 0, ticks, b"p", 1),
    ]);
    read(bytes).packets[0].0.epoch
}

#[test]
fn resolution_defaults_to_microseconds() {
    assert_eq!(
        one_packet_epoch(None, 1_700_000_000_500_000, false),
        1_700_000_000.5
    );
    assert_eq!(
        one_packet_epoch(Some(6), 1_700_000_000_500_000, true),
        1_700_000_000.5
    );
}

#[test]
fn power_of_ten_resolutions_are_exact() {
    for be in [false, true] {
        assert_eq!(
            one_packet_epoch(Some(0), 1_700_000_000, be),
            1_700_000_000.0
        );
        assert_eq!(
            one_packet_epoch(Some(3), 1_700_000_000_250, be),
            1_700_000_000.25
        );
        assert_eq!(
            one_packet_epoch(Some(9), 1_700_000_000_500_000_000, be),
            1_700_000_000.5
        );
        assert_eq!(
            one_packet_epoch(Some(1), 17_000_000_005, be),
            1_700_000_000.5
        );
    }
}

#[test]
fn nanosecond_ticks_keep_the_fraction() {
    let got = one_packet_epoch(Some(9), 1_700_000_000_123_456_789, false);
    assert_eq!(got, 1_700_000_000.0 + 123_456_789.0 / 1e9);
    assert!((got - 1_700_000_000.123_456_7).abs() < 5e-7);
}

#[test]
fn base_two_resolutions_are_exact() {
    for be in [false, true] {
        let res = 0x80 | 10;
        let ticks = 1_700_000_000u64 * 1024 + 512;
        assert_eq!(one_packet_epoch(Some(res), ticks, be), 1_700_000_000.5);
        assert_eq!(one_packet_epoch(Some(0x80), 7, be), 7.0);
    }
}

#[test]
fn ticks_use_both_halves_of_the_timestamp() {
    let ticks = (3u64 << 32) | 5;
    assert_eq!(one_packet_epoch(Some(0), ticks, false), ticks as f64);
}

#[test]
fn an_unrepresentable_resolution_stops_the_read_after_earlier_packets() {
    let bytes = cat(&[
        ng_shb(false),
        ng_idb(false, ETH, 0, None),
        ng_epb(false, 0, 1_000_000, b"a", 1),
        ng_idb(false, ETH, 0, Some(20)),
        ng_epb(false, 1, 5, b"b", 1),
    ]);
    let got = read(bytes);
    assert_eq!(got.packets.len(), 1);
    assert!(matches!(got.error, Some(ReadError::Truncated(_))));
}
