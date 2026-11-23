use std::path::PathBuf;

use wl_model::{CaptureProperties, ClockZone};

use super::*;
use crate::reader::LinkType;
use crate::test_util::{Frame, PcapStyle, pcap_bytes, pcapng_bytes, sample_frames};

pub(super) fn frame(epoch: f64, len: usize) -> Frame {
    Frame::new(epoch, vec![0; len])
}

pub(super) fn props(bytes: Vec<u8>) -> CaptureProperties {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("x.cap");
    std::fs::write(&path, bytes).expect("write");
    read(&path, ClockZone::Utc).expect("read")
}

pub(super) fn pcap(frames: &[Frame]) -> CaptureProperties {
    props(pcap_bytes(frames, PcapStyle::default()))
}

#[test]
fn empty_pcap_has_no_times_and_zero_rates() {
    let p = pcap(&[]);
    assert_eq!((p.packets, p.data_size, p.file_size), (0, 0, 24));
    assert_eq!(
        (p.first_packet.as_str(), p.last_packet.as_str()),
        ("n/a", "n/a")
    );
    assert_eq!(p.strict_order, Some(true));
    assert_eq!(
        (p.duration, p.bytes_per_sec, p.avg_packet_size),
        (0.0, 0.0, 0.0)
    );
    assert_eq!(
        (p.file_type.as_str(), p.encapsulation.as_str()),
        ("pcap", "ether")
    );
    assert_eq!(p.interfaces.len(), 1);
    assert_eq!(p.interfaces[0].packets, "0");
    assert_eq!(p.interfaces[0].capture_length, "262144");
}

#[test]
fn one_packet_has_a_duration_of_zero_and_no_rates() {
    let p = pcap(&[frame(100.5, 60)]);
    assert_eq!((p.packets, p.data_size), (1, 60));
    assert_eq!(p.duration, 0.0);
    assert_eq!(
        (p.bytes_per_sec, p.bits_per_sec, p.avg_packets_per_sec),
        (0.0, 0.0, 0.0)
    );
    assert_eq!(p.avg_packet_size, 60.0);
    assert_eq!(p.first_packet, "1970-01-01 00:01:40.500000");
    assert_eq!(p.first_packet, p.last_packet);
}

#[test]
fn rates_come_from_the_wire_bytes_and_the_duration() {
    let p = pcap(&[frame(100.0, 40), frame(101.0, 80)]);
    assert_eq!(p.duration, 1.0);
    assert_eq!((p.bytes_per_sec, p.bits_per_sec), (120.0, 960.0));
    assert_eq!((p.avg_packet_size, p.avg_packets_per_sec), (60.0, 2.0));
}

#[test]
fn snaplen_cut_packets_count_their_length_on_the_wire() {
    let mut cut = frame(100.0, 40);
    cut.orig_len = Some(1500);
    let p = pcap(&[cut, frame(101.0, 60)]);
    assert_eq!(p.data_size, 1560);
    assert_eq!(p.avg_packet_size, 780.0);
}

#[test]
fn out_of_order_times_clear_the_flag_and_use_the_extremes() {
    let p = pcap(&[
        frame(100.0, 60),
        frame(100.5, 60),
        frame(99.0, 60),
        frame(102.5, 60),
    ]);
    assert_eq!(p.strict_order, Some(false));
    assert_eq!(p.duration, 3.5);
    assert_eq!(p.first_packet, "1970-01-01 00:01:39.000000");
    assert_eq!(p.last_packet, "1970-01-01 00:01:42.500000");
}

#[test]
fn equal_times_are_still_in_order() {
    let p = pcap(&[frame(100.0, 60), frame(100.0, 60)]);
    assert_eq!((p.strict_order, p.duration), (Some(true), 0.0));
}

#[test]
fn pcap_and_pcapng_report_the_same_numbers() {
    let frames = sample_frames();
    let a = pcap(&frames);
    let b = props(pcapng_bytes(&frames));
    assert_eq!(b.file_type, "pcapng");
    for (x, y) in [(a.packets, b.packets), (a.data_size, b.data_size)] {
        assert_eq!(x, y);
    }
    assert_eq!(
        (a.first_packet, a.last_packet),
        (b.first_packet, b.last_packet)
    );
    assert!((a.duration - b.duration).abs() < 1e-9);
    assert_eq!(a.encapsulation, b.encapsulation);
}

#[test]
fn nanosecond_pcap_keeps_nine_decimals() {
    let style = PcapStyle {
        nanos: true,
        ..PcapStyle::default()
    };
    let p = props(pcap_bytes(&[frame(100.25, 60), frame(101.0, 60)], style));
    assert_eq!(p.file_type, "nsecpcap");
    assert_eq!(p.first_packet, "1970-01-01 00:01:40.250000000");
}

#[test]
fn big_endian_pcap_reads_like_little_endian() {
    let style = PcapStyle {
        big_endian: true,
        ..PcapStyle::default()
    };
    let p = props(pcap_bytes(&[frame(100.0, 60), frame(101.0, 60)], style));
    assert_eq!((p.packets, p.duration), (2, 1.0));
}

#[test]
fn link_types_are_named_like_wireshark() {
    let named = |link| {
        pcap_bytes(
            &[frame(1.0, 60)],
            PcapStyle {
                link_type: link,
                ..PcapStyle::default()
            },
        )
    };
    let p = props(named(105));
    assert_eq!(p.encapsulation, "ieee-802-11");
    assert_eq!(
        p.interfaces[0].encapsulation,
        "IEEE 802.11 Wireless LAN (20 - ieee-802-11)"
    );
    assert_eq!(
        props(named(101)).interfaces[0].encapsulation,
        "Raw IP (7 - rawip)"
    );
    assert_eq!(props(named(9999)).encapsulation, "");
}

#[test]
fn name_and_size_are_the_ones_of_the_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path: PathBuf = dir.path().join("named.pcap");
    let bytes = pcap_bytes(&sample_frames(), PcapStyle::default());
    std::fs::write(&path, &bytes).expect("write");
    let p = read(&path, ClockZone::Utc).expect("read");
    assert_eq!(p.file_name, path.to_string_lossy());
    assert_eq!(p.file_size, bytes.len() as u64);
}

#[test]
fn missing_garbage_and_damaged_files_are_errors() {
    let dir = tempfile::tempdir().expect("tempdir");
    assert!(read(&dir.path().join("none.pcap"), ClockZone::Utc).is_err());
    let garbage = dir.path().join("g.pcap");
    std::fs::write(&garbage, b"this is not a capture file at all").expect("write");
    assert!(read(&garbage, ClockZone::Utc).is_err());
    let mut bytes = pcap_bytes(&sample_frames(), PcapStyle::default());
    bytes.truncate(bytes.len() - 10);
    let cut = dir.path().join("cut.pcap");
    std::fs::write(&cut, bytes).expect("write");
    assert!(read(&cut, ClockZone::Utc).is_err());
}

#[test]
fn stamps_format_in_utc_with_the_requested_decimals() {
    use crate::reader::Stamp;
    let at = |secs, nanos, digits| {
        stamp::format(
            &Stamp {
                secs,
                nanos,
                digits,
            },
            ClockZone::Utc,
        )
        .expect("time")
    };
    assert_eq!(at(0, 0, 0), "1970-01-01 00:00:00");
    assert_eq!(at(951_782_400, 5, 9), "2000-02-29 00:00:00.000000005");
    assert_eq!(at(1_700_000_000, 123_456_789, 3), "2023-11-14 22:13:20.123");
    assert_eq!(
        at(4_102_444_799, 999_999_999, 6),
        "2099-12-31 23:59:59.999999"
    );
    assert_eq!(at(4_107_542_400, 0, 0), "2100-03-01 00:00:00");
}

#[test]
fn links_without_a_table_entry_have_no_name() {
    assert!(links::encap_of(LinkType::Other(1234)).is_none());
}
