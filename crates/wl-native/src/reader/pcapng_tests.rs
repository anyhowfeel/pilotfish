use crate::reader::tests::{Drained, drain_bytes};
use crate::test_util::{
    Frame, ng_block, ng_epb, ng_idb, ng_shb, ng_spb, pcapng_bytes, sample_frames,
};

use super::super::{LinkType, ReadError};

const ETH: u16 = 1;

pub fn cat(blocks: &[Vec<u8>]) -> Vec<u8> {
    blocks.concat()
}

pub fn read(bytes: Vec<u8>) -> Drained {
    drain_bytes(bytes).expect("open")
}

#[test]
fn writer_output_reads_back_in_order() {
    let frames = sample_frames();
    let got = read(pcapng_bytes(&frames));
    assert!(got.error.is_none());
    assert_eq!(got.packets.len(), frames.len());
    for (i, (meta, data)) in got.packets.iter().enumerate() {
        assert_eq!(meta.no, i as u64 + 1);
        assert_eq!(meta.link, LinkType::Ethernet);
        assert_eq!(*data, frames[i].data);
        assert!((meta.epoch - frames[i].epoch).abs() < 1e-6);
    }
}

#[test]
fn both_byte_orders_read_the_same() {
    let build = |be| {
        cat(&[
            ng_shb(be),
            ng_idb(be, ETH, 65535, None),
            ng_epb(be, 0, 1_500_000, b"one", 3),
            ng_epb(be, 0, 2_250_000, b"two!", 4),
        ])
    };
    let le = read(build(false));
    let be = read(build(true));
    assert!(le.error.is_none() && be.error.is_none());
    assert_eq!(le.packets, be.packets);
    assert_eq!(le.packets[0].0.epoch, 1.5);
    assert_eq!(le.packets[1].0.epoch, 2.25);
    assert_eq!(le.packets[1].1, b"two!");
}

#[test]
fn interfaces_keep_their_own_link_type_and_resolution() {
    let bytes = cat(&[
        ng_shb(false),
        ng_idb(false, 1, 0, Some(6)),
        ng_idb(false, 113, 0, Some(9)),
        ng_idb(false, 101, 0, Some(0)),
        ng_epb(false, 1, 2_000_000_000, b"sll", 3),
        ng_epb(false, 0, 3_000_000, b"eth", 3),
        ng_epb(false, 2, 9, b"raw", 3),
        ng_epb(false, 1, 4_500_000_000, b"sll2", 4),
    ]);
    let got = read(bytes).packets;
    let seen: Vec<_> = got.iter().map(|(m, _)| (m.no, m.link, m.epoch)).collect();
    assert_eq!(
        seen,
        vec![
            (1, LinkType::LinuxSll, 2.0),
            (2, LinkType::Ethernet, 3.0),
            (3, LinkType::RawIp, 9.0),
            (4, LinkType::LinuxSll, 4.5),
        ]
    );
}

#[test]
fn unknown_link_codes_are_kept() {
    let bytes = cat(&[
        ng_shb(false),
        ng_idb(false, 276, 0, None),
        ng_idb(false, 147, 0, None),
        ng_epb(false, 0, 0, b"a", 1),
        ng_epb(false, 1, 0, b"b", 1),
    ]);
    let got = read(bytes).packets;
    assert_eq!(got[0].0.link, LinkType::LinuxSll2);
    assert_eq!(got[1].0.link, LinkType::Other(147));
}

#[test]
fn simple_packets_reuse_the_previous_timestamp() {
    for be in [false, true] {
        let bytes = cat(&[
            ng_shb(be),
            ng_idb(be, ETH, 0, None),
            ng_spb(be, b"first", 5),
            ng_epb(be, 0, 7_250_000, b"epb", 3),
            ng_spb(be, b"padded", 6),
            ng_spb(be, b"cut!", 1500),
        ]);
        let got = read(bytes).packets;
        let seen: Vec<_> = got
            .iter()
            .map(|(m, d)| (m.no, m.epoch, m.orig_len, d.clone()))
            .collect();
        assert_eq!(seen[0], (1, 0.0, 5, b"first".to_vec()));
        assert_eq!(seen[1], (2, 7.25, 3, b"epb".to_vec()));
        assert_eq!(seen[2], (3, 7.25, 6, b"padded".to_vec()));
        assert_eq!(seen[3], (4, 7.25, 1500, b"cut!".to_vec()));
    }
}

#[test]
fn simple_packets_are_cut_at_the_snap_length() {
    let bytes = cat(&[
        ng_shb(false),
        ng_idb(false, ETH, 4, None),
        ng_spb(false, b"0123456789", 10),
    ]);
    let got = read(bytes).packets;
    assert_eq!(got[0].1, b"0123");
    assert_eq!(got[0].0.orig_len, 10);
}

#[test]
fn a_simple_packet_without_an_interface_is_damage() {
    let got = read(cat(&[ng_shb(false), ng_spb(false, b"x", 1)]));
    assert!(got.packets.is_empty());
    assert!(matches!(got.error, Some(ReadError::Truncated(_))));
}

#[test]
fn padding_is_not_part_of_the_packet() {
    let bytes = cat(&[
        ng_shb(false),
        ng_idb(false, ETH, 0, None),
        ng_epb(false, 0, 1, b"12345", 5),
    ]);
    assert_eq!(read(bytes).packets[0].1, b"12345");
}

#[test]
fn snap_length_cut_keeps_the_captured_bytes_and_the_wire_length() {
    let mut f = Frame::new(1.0, vec![9; 64]);
    f.orig_len = Some(9000);
    let (meta, data) = &read(pcapng_bytes(&[f])).packets[0];
    assert_eq!(meta.orig_len, 9000);
    assert_eq!(data.len(), 64);
}

#[test]
fn other_block_types_are_skipped_and_not_counted() {
    let bytes = cat(&[
        ng_shb(false),
        ng_idb(false, ETH, 0, None),
        ng_block(4, &[0, 0, 0, 0], false),
        ng_epb(false, 0, 1_000_000, b"a", 1),
        ng_block(5, &[0; 20], false),
        ng_block(0x0000_0bad, b"custom data", false),
        ng_block(0x1234_5678, &[1, 2, 3], false),
        ng_epb(false, 0, 2_000_000, b"b", 1),
    ]);
    let got = read(bytes);
    assert!(got.error.is_none());
    let numbers: Vec<_> = got.packets.iter().map(|(m, _)| m.no).collect();
    assert_eq!(numbers, vec![1, 2]);
}

#[test]
fn a_new_section_resets_interfaces_and_may_change_byte_order() {
    let bytes = cat(&[
        ng_shb(false),
        ng_idb(false, 1, 0, Some(6)),
        ng_epb(false, 0, 1_000_000, b"a", 1),
        ng_shb(true),
        ng_idb(true, 113, 0, Some(3)),
        ng_epb(true, 0, 2500, b"b", 1),
        ng_shb(false),
        ng_idb(false, 101, 0, None),
        ng_epb(false, 0, 3_000_000, b"c", 1),
    ]);
    let got = read(bytes);
    assert!(got.error.is_none());
    let seen: Vec<_> = got
        .packets
        .iter()
        .map(|(m, _)| (m.no, m.link, m.epoch))
        .collect();
    assert_eq!(
        seen,
        vec![
            (1, LinkType::Ethernet, 1.0),
            (2, LinkType::LinuxSll, 2.5),
            (3, LinkType::RawIp, 3.0),
        ]
    );
}

#[test]
fn interface_ids_do_not_leak_across_sections() {
    let bytes = cat(&[
        ng_shb(false),
        ng_idb(false, 1, 0, None),
        ng_idb(false, 1, 0, None),
        ng_epb(false, 1, 1, b"a", 1),
        ng_shb(false),
        ng_idb(false, 1, 0, None),
        ng_epb(false, 1, 1, b"b", 1),
    ]);
    let got = read(bytes);
    assert_eq!(got.packets.len(), 1);
    assert!(matches!(got.error, Some(ReadError::Truncated(ref m)) if m.contains("interface 1")));
}

#[test]
fn packets_before_any_interface_are_damage() {
    let got = read(cat(&[ng_shb(false), ng_epb(false, 0, 1, b"a", 1)]));
    assert!(got.packets.is_empty());
    assert!(matches!(got.error, Some(ReadError::Truncated(_))));
}

#[test]
fn section_header_only_is_an_empty_capture() {
    let got = read(ng_shb(false));
    assert!(got.packets.is_empty() && got.error.is_none());
}

#[test]
fn a_cut_anywhere_returns_the_packets_before_it() {
    let blocks = [
        ng_shb(false),
        ng_idb(false, ETH, 0, None),
        ng_epb(false, 0, 1_000_000, b"first", 5),
        ng_block(4, &[0; 4], false),
        ng_epb(false, 0, 2_000_000, b"second", 6),
    ];
    let bytes = cat(&blocks);
    let whole = read(bytes.clone());
    assert!(whole.error.is_none());
    let whole = whole.packets;
    let mut ends = Vec::new();
    let mut at = 0;
    for b in &blocks {
        at += b.len();
        ends.push(at);
    }
    for cut in 4..bytes.len() {
        let Ok(got) = drain_bytes(bytes[..cut].to_vec()) else {
            assert!(cut < ends[0], "cut {cut}");
            continue;
        };
        let packets_done = [ends[2], ends[4]].iter().filter(|e| **e <= cut).count();
        assert_eq!(got.packets, whole[..packets_done], "cut {cut}");
        if ends.contains(&cut) {
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
fn a_packet_larger_than_the_initial_buffer_is_read() {
    let big = vec![0x42; 1 << 20];
    let bytes = cat(&[
        ng_shb(false),
        ng_idb(false, ETH, 0, None),
        ng_epb(false, 0, 1, &big, big.len() as u32),
        ng_epb(false, 0, 2, b"after", 5),
    ]);
    let got = read(bytes).packets;
    assert_eq!(got.len(), 2);
    assert_eq!(got[0].1, big);
    assert_eq!(got[1].1, b"after");
}

#[test]
fn block_lengths_that_lie_are_damage() {
    let good = cat(&[
        ng_shb(false),
        ng_idb(false, ETH, 0, None),
        ng_epb(false, 0, 1, b"ok", 2),
    ]);
    for lie in [0u32, 4, 11, 13, 0x7fff_fff0, 0xffff_fffc, 0xffff_ffff] {
        let mut bytes = good.clone();
        bytes.extend_from_slice(&6u32.to_le_bytes());
        bytes.extend_from_slice(&lie.to_le_bytes());
        bytes.extend_from_slice(&[0; 40]);
        let got = read(bytes);
        assert_eq!(got.packets.len(), 1, "lie {lie}");
        assert!(
            matches!(got.error, Some(ReadError::Truncated(_))),
            "lie {lie}"
        );
    }
}
