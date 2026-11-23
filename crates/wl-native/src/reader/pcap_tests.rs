use crate::reader::tests::{drain, drain_bytes};
use crate::test_util::{Frame, PcapStyle, pcap_bytes, sample_frames};

use super::super::{LinkType, ReadError};

type Record = (u32, u32, Vec<u8>, u32);

fn raw_pcap(be: bool, nanos: bool, link: u32, records: &[Record]) -> Vec<u8> {
    let w32 = |v: u32| if be { v.to_be_bytes() } else { v.to_le_bytes() };
    let w16 = |v: u16| if be { v.to_be_bytes() } else { v.to_le_bytes() };
    let mut out = w32(if nanos { 0xa1b2_3c4d } else { 0xa1b2_c3d4 }).to_vec();
    out.extend_from_slice(&w16(2));
    out.extend_from_slice(&w16(4));
    out.extend_from_slice(&[0; 8]);
    out.extend_from_slice(&w32(65535));
    out.extend_from_slice(&w32(link));
    for (sec, sub, data, orig) in records {
        for v in [*sec, *sub, data.len() as u32, *orig] {
            out.extend_from_slice(&w32(v));
        }
        out.extend_from_slice(data);
    }
    out
}

fn rec(sec: u32, sub: u32, data: &[u8]) -> Record {
    (sec, sub, data.to_vec(), data.len() as u32)
}

#[test]
fn every_endianness_and_resolution_reads_the_same_packets() {
    let frames = sample_frames();
    for big_endian in [false, true] {
        for nanos in [false, true] {
            let style = PcapStyle {
                nanos,
                big_endian,
                link_type: 1,
            };
            let got = drain_bytes(pcap_bytes(&frames, style)).expect("open");
            assert!(got.error.is_none());
            assert_eq!(got.packets.len(), frames.len());
            for (i, (meta, data)) in got.packets.iter().enumerate() {
                assert_eq!(meta.no, i as u64 + 1);
                assert_eq!(meta.link, LinkType::Ethernet);
                assert_eq!(*data, frames[i].data);
                assert_eq!(meta.orig_len as usize, frames[i].data.len());
                assert!((meta.epoch - frames[i].epoch).abs() < 1e-6);
            }
        }
    }
}

#[test]
fn microsecond_timestamps_are_exact() {
    for be in [false, true] {
        let bytes = raw_pcap(
            be,
            false,
            1,
            &[rec(1_700_000_000, 123_456, b"a"), rec(5, 0, b"b")],
        );
        let got = drain_bytes(bytes).expect("open").packets;
        assert_eq!(got[0].0.epoch, 1_700_000_000.0 + 123_456.0 / 1e6);
        assert_eq!(got[1].0.epoch, 5.0);
    }
}

#[test]
fn nanosecond_timestamps_are_exact() {
    for be in [false, true] {
        let bytes = raw_pcap(
            be,
            true,
            1,
            &[rec(1_700_000_000, 123_456_789, b"a"), rec(0, 1, b"b")],
        );
        let got = drain_bytes(bytes).expect("open").packets;
        assert_eq!(got[0].0.epoch, 1_700_000_000.0 + 123_456_789.0 / 1e9);
        assert_eq!(got[1].0.epoch, 1e-9);
    }
}

#[test]
fn microsecond_file_does_not_read_fractions_as_nanoseconds() {
    let bytes = raw_pcap(false, false, 1, &[rec(10, 500_000, b"x")]);
    assert_eq!(drain_bytes(bytes).expect("open").packets[0].0.epoch, 10.5);
}

#[test]
fn link_type_comes_from_the_global_header() {
    let cases = [
        (1, LinkType::Ethernet),
        (0, LinkType::Null),
        (101, LinkType::RawIp),
        (12, LinkType::RawIp),
        (14, LinkType::RawIp),
        (113, LinkType::LinuxSll),
        (276, LinkType::LinuxSll2),
        (105, LinkType::Other(105)),
    ];
    for (code, want) in cases {
        let bytes = raw_pcap(false, false, code, &[rec(1, 0, b"abcd")]);
        let got = drain_bytes(bytes).expect("open").packets;
        assert_eq!(got[0].0.link, want, "code {code}");
    }
}

#[test]
fn snap_length_cut_keeps_the_captured_bytes_and_the_wire_length() {
    let mut f = Frame::new(1.0, vec![7; 60]);
    f.orig_len = Some(1514);
    let got = drain_bytes(pcap_bytes(&[f], PcapStyle::default())).expect("open");
    let (meta, data) = &got.packets[0];
    assert_eq!(meta.orig_len, 1514);
    assert_eq!(data.len(), 60);
}

#[test]
fn header_only_file_is_empty_and_stays_empty() {
    let bytes = raw_pcap(false, false, 1, &[]);
    let mut source = crate::reader::from_reader(std::io::Cursor::new(bytes)).expect("open");
    let mut data = vec![1];
    assert_eq!(source.next_packet(&mut data), Ok(None));
    assert_eq!(source.next_packet(&mut data), Ok(None));
}

#[test]
fn zero_length_packets_are_packets() {
    let bytes = raw_pcap(false, false, 1, &[rec(1, 0, b""), rec(2, 0, b"z")]);
    let got = drain_bytes(bytes).expect("open").packets;
    assert_eq!(got.len(), 2);
    assert!(got[0].1.is_empty());
}

#[test]
fn data_buffer_is_replaced_not_appended() {
    let bytes = raw_pcap(
        false,
        false,
        1,
        &[rec(1, 0, b"long packet"), rec(2, 0, b"ab")],
    );
    let got = drain_bytes(bytes).expect("open").packets;
    assert_eq!(got[1].1, b"ab");
}

#[test]
fn a_cut_anywhere_returns_the_packets_before_it() {
    let bytes = raw_pcap(
        false,
        false,
        1,
        &[rec(1, 0, b"first"), rec(2, 0, b"second")],
    );
    let whole = drain_bytes(bytes.clone()).expect("open").packets;
    let boundaries = [24, 24 + 16 + 5, bytes.len()];
    for cut in 4..bytes.len() {
        let Ok(got) = drain_bytes(bytes[..cut].to_vec()) else {
            assert!(cut < 24, "cut {cut}");
            continue;
        };
        let complete = boundaries.iter().filter(|b| **b <= cut && **b > 24).count();
        assert_eq!(got.packets, whole[..complete], "cut {cut}");
        if boundaries.contains(&cut) {
            assert!(got.error.is_none(), "cut {cut}");
        } else {
            assert!(
                matches!(got.error, Some(ReadError::Truncated(_))),
                "cut {cut}"
            );
        }
    }
}

#[test]
fn many_packets_cross_buffer_refills() {
    let records: Vec<Record> = (0..3000u32)
        .map(|i| rec(1000 + i, i, &[(i % 251) as u8; 1000]))
        .collect();
    let got = drain_bytes(raw_pcap(true, false, 1, &records)).expect("open");
    assert!(got.error.is_none());
    assert_eq!(got.packets.len(), 3000);
    for (i, (meta, data)) in got.packets.iter().enumerate() {
        assert_eq!(meta.no, i as u64 + 1);
        assert_eq!(data[0], (i % 251) as u8);
        assert_eq!(data.len(), 1000);
    }
}

#[test]
fn a_packet_larger_than_the_initial_buffer_grows_it_once_needed() {
    let big = vec![0x42; 1 << 20];
    let bytes = raw_pcap(
        false,
        false,
        1,
        &[rec(1, 0, b"small"), rec(2, 0, &big), rec(3, 0, b"end")],
    );
    let got = drain_bytes(bytes).expect("open").packets;
    assert_eq!(got.len(), 3);
    assert_eq!(got[1].1, big);
    assert_eq!(got[2].1, b"end");
}

#[test]
fn a_lying_capture_length_is_damage_not_an_allocation() {
    let mut bytes = raw_pcap(false, false, 1, &[rec(1, 0, b"ok")]);
    bytes.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0]);
    bytes.extend_from_slice(&0xffff_ff00u32.to_le_bytes());
    bytes.extend_from_slice(&0xffff_ff00u32.to_le_bytes());
    bytes.extend_from_slice(b"short");
    let got = drain_bytes(bytes).expect("open");
    assert_eq!(got.packets.len(), 1);
    assert!(matches!(got.error, Some(ReadError::Truncated(_))));
}

#[test]
fn source_in_a_buffer_never_reads_the_whole_file() {
    let mut source = super::PcapSource::new(
        std::io::Cursor::new(raw_pcap(false, false, 1, &[rec(1, 0, b"x")])),
        crate::reader::fill::IoErrors::default(),
    )
    .expect("source");
    assert_eq!(
        source.buffer_capacity(),
        crate::reader::stream::INITIAL_BUFFER
    );
    let got = drain(&mut source);
    assert_eq!(got.packets.len(), 1);
}
