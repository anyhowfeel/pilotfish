//! `basic` on capture files: which frame it finds, what it returns and how it fails.

use std::net::Ipv4Addr;
use std::path::PathBuf;

use tempfile::TempDir;

use super::*;
use crate::test_util::*;

const A: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const B: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);

fn packets() -> Vec<Vec<u8>> {
    (0..7u16)
        .map(|i| match i % 3 {
            0 => tcp4((A, 1000 + i), (B, 80), SYN, 100 + u32::from(i), 0, &[]),
            1 => udp4((A, 2000 + i), (B, 53), &dns_query_payload(i, "a.test")),
            _ => icmp4_echo(A, B, i, i),
        })
        .collect()
}

fn frames() -> Vec<Frame> {
    packets()
        .into_iter()
        .enumerate()
        .map(|(i, p)| Frame::new(1_700_000_000.0 + i as f64, p))
        .collect()
}

fn pcap_file(dir: &TempDir) -> PathBuf {
    let path = dir.path().join("a.pcap");
    write_pcap(&path, &frames(), PcapStyle::default());
    path
}

fn pcapng_file(dir: &TempDir) -> PathBuf {
    let path = dir.path().join("a.pcapng");
    write_pcapng(&path, &frames());
    path
}

fn check_frames(path: &Path) {
    let packets = packets();
    for no in [1, 4, 7] {
        let d = basic(path, no).expect("frame");
        assert_eq!(d.frame_no, no);
        assert_eq!(d.bytes, packets[no as usize - 1]);
        let len = d.bytes.len();
        assert!(
            d.layers[0].label.starts_with(&format!(
                "Frame {no}: {len} bytes on wire ({} bits), {len} bytes captured",
                len * 8
            )),
            "{}",
            d.layers[0].label
        );
    }
}

#[test]
fn pcap_gives_the_first_middle_and_last_frame() {
    let dir = tempfile::tempdir().expect("tempdir");
    check_frames(&pcap_file(&dir));
}

#[test]
fn pcapng_gives_the_first_middle_and_last_frame() {
    let dir = tempfile::tempdir().expect("tempdir");
    check_frames(&pcapng_file(&dir));
}

#[test]
fn frame_zero_and_past_the_end_are_not_found() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = pcap_file(&dir);
    for no in [0, 8, 1000] {
        assert_eq!(
            basic(&path, no),
            Err(CaptureError::Other(format!(
                "frame {no} not found in {}",
                path.display()
            )))
        );
    }
}

#[test]
fn a_missing_file_is_an_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    let r = basic(&dir.path().join("none.pcap"), 1);
    assert!(matches!(r, Err(CaptureError::Other(_))));
}

#[test]
fn a_truncated_file_serves_the_frames_before_the_cut() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = pcap_file(&dir);
    let whole = std::fs::read(&path).expect("read");
    let cut = dir.path().join("cut.pcap");
    std::fs::write(&cut, &whole[..whole.len() - 10]).expect("write");
    assert_eq!(basic(&cut, 3).expect("frame 3").bytes, packets()[2]);
    assert!(matches!(basic(&cut, 7), Err(CaptureError::Other(_))));
}

#[test]
fn a_file_that_is_not_a_capture_is_an_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("junk.pcap");
    std::fs::write(&path, b"this is not a capture file").expect("write");
    assert!(matches!(basic(&path, 1), Err(CaptureError::Other(_))));
}

fn link_case(link_type: u32, bytes: Vec<u8>) -> FrameDetail {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("l.pcap");
    let style = PcapStyle {
        link_type,
        ..PcapStyle::default()
    };
    write_pcap(&path, &[Frame::new(1_700_000_000.0, bytes)], style);
    basic(&path, 1).expect("frame")
}

fn ip_packet() -> Vec<u8> {
    ip4_packet(A, B, 17, 1, 0, &udp_datagram((5, 6), b"x"))
}

fn with_prefix(prefix: &[u8]) -> Vec<u8> {
    [prefix, &ip_packet()].concat()
}

#[test]
fn every_link_type_names_its_header_and_finds_the_ip_layer() {
    let sll = [&[0u8; 14][..], &[8, 0]].concat();
    let sll2 = [&[8u8, 0][..], &[0; 18]].concat();
    let cases: [(u32, Vec<u8>, Option<&str>); 6] = [
        (
            1,
            eth_frame(0x0800, &ip_packet()),
            Some("Ethernet II, Src: "),
        ),
        (0, with_prefix(&[2, 0, 0, 0]), Some("Null/Loopback")),
        (101, ip_packet(), Some("Raw packet data")),
        (113, with_prefix(&sll), Some("Linux cooked capture v1")),
        (276, with_prefix(&sll2), Some("Linux cooked capture v2")),
        (105, ip_packet(), None),
    ];
    for (link_type, bytes, header) in cases {
        let d = link_case(link_type, bytes.clone());
        assert_eq!(d.bytes, bytes, "link {link_type}");
        let labels: Vec<&str> = d.layers.iter().map(|l| l.label.as_str()).collect();
        match header {
            Some(h) => {
                assert!(labels[1].starts_with(h), "link {link_type}: {labels:?}");
                assert_eq!(labels.len(), 4, "link {link_type}: {labels:?}");
                assert!(labels[2].starts_with("Internet Protocol Version 4"));
                assert!(labels[3].starts_with("User Datagram Protocol"));
            }
            None => assert_eq!(labels.len(), 1, "{labels:?}"),
        }
    }
}
