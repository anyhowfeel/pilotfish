use std::net::{Ipv4Addr, Ipv6Addr};

use super::*;
use crate::test_util::{ip4_packet, ip6_packet, udp_datagram};

const A: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const B: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);

fn ip(l: NetLayer<'_>) -> Ip<'_> {
    match l {
        NetLayer::Ip(ip) => ip,
        other => panic!("not ip: {other:?}"),
    }
}

#[test]
fn ipv4_header_fields() {
    let pkt = ip4_packet(A, B, 17, 0x1234, 0x4000, &udp_datagram((1, 2), b"hi"));
    let i = ip(parse(Net::Ipv4, &pkt, 0));
    assert_eq!((i.version, i.src, i.dst), (4, A.into(), B.into()));
    assert_eq!((i.proto, i.first_proto, i.ttl), (17, 17, 64));
    assert_eq!((i.header_len, i.payload_len, i.payload.len()), (20, 10, 10));
    assert_eq!(i.frag, None);
}

#[test]
fn ethernet_padding_after_the_ip_packet_is_not_payload() {
    let mut pkt = ip4_packet(A, B, 17, 1, 0, &udp_datagram((1, 2), b"hi"));
    pkt.extend_from_slice(&[0; 20]);
    let i = ip(parse(Net::Ipv4, &pkt, 0));
    assert_eq!((i.payload_len, i.payload.len()), (10, 10));
}

#[test]
fn a_cut_capture_keeps_the_declared_length() {
    let pkt = ip4_packet(A, B, 6, 1, 0, &[0; 100]);
    let i = ip(parse(Net::Ipv4, &pkt[..60], 0));
    assert_eq!((i.payload_len, i.payload.len()), (100, 40));
}

#[test]
fn zero_total_length_means_the_captured_length() {
    let mut pkt = ip4_packet(A, B, 6, 1, 0, &[0; 30]);
    pkt[2] = 0;
    pkt[3] = 0;
    let i = ip(parse(Net::Ipv4, &pkt, 0));
    assert_eq!((i.payload_len, i.payload.len()), (30, 30));
}

#[test]
fn ipv4_fragments_report_offset_and_more_flag() {
    let first = ip4_packet(A, B, 17, 0xbeef, 0x2000, &[0; 16]);
    let f = ip(parse(Net::Ipv4, &first, 0)).frag;
    assert_eq!(
        f,
        Some(Frag {
            offset: 0,
            more: true,
            id: 0xbeef
        })
    );
    let last = ip4_packet(A, B, 17, 0xbeef, 0x00b9, &[0; 8]);
    let f = ip(parse(Net::Ipv4, &last, 0)).frag;
    assert_eq!(
        f,
        Some(Frag {
            offset: 185 * 8,
            more: false,
            id: 0xbeef
        })
    );
    let df = ip4_packet(A, B, 17, 1, 0x4000, &[0; 8]);
    assert_eq!(ip(parse(Net::Ipv4, &df, 0)).frag, None);
}

#[test]
fn bad_or_short_ipv4_headers_are_broken_not_missing() {
    let good = ip4_packet(A, B, 6, 1, 0, &[0; 20]);
    for n in 0..20 {
        assert_eq!(
            parse(Net::Ipv4, &good[..n], 0),
            NetLayer::Broken(Net::Ipv4),
            "{n}"
        );
    }
    let mut bad_version = good.clone();
    bad_version[0] = 0x65;
    assert_eq!(
        parse(Net::Ipv4, &bad_version, 0),
        NetLayer::Broken(Net::Ipv4)
    );
    let mut small_ihl = good.clone();
    small_ihl[0] = 0x44;
    assert_eq!(parse(Net::Ipv4, &small_ihl, 0), NetLayer::Broken(Net::Ipv4));
    let mut long_ihl = good;
    long_ihl[0] = 0x4f;
    assert_eq!(
        parse(Net::Ipv4, &long_ihl[..40], 0),
        NetLayer::Broken(Net::Ipv4)
    );
}

#[test]
fn ipv4_options_extend_the_header() {
    let mut pkt = ip4_packet(A, B, 17, 1, 0, &[]);
    pkt[0] = 0x46;
    pkt.splice(20..20, [1, 1, 1, 0]);
    pkt.extend_from_slice(&udp_datagram((1, 2), b""));
    let total = pkt.len() as u16;
    pkt[2..4].copy_from_slice(&total.to_be_bytes());
    let i = ip(parse(Net::Ipv4, &pkt, 0));
    assert_eq!((i.header_len, i.payload.len()), (24, 8));
}

#[test]
fn the_offset_is_where_the_header_starts() {
    let mut frame = vec![0xaa; 14];
    frame.extend(ip4_packet(A, B, 6, 1, 0, &[0; 20]));
    assert_eq!(ip(parse(Net::Ipv4, &frame, 14)).offset, 14);
    assert_eq!(parse(Net::Ipv4, &frame, 500), NetLayer::Broken(Net::Ipv4));
}

fn v6(a: u16) -> Ipv6Addr {
    Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, a)
}

#[test]
fn ipv6_header_fields() {
    let pkt = ip6_packet(v6(1), v6(2), 17, &udp_datagram((1, 2), b"abc"));
    let i = ip(parse(Net::Ipv6, &pkt, 0));
    assert_eq!((i.version, i.src, i.dst), (6, v6(1).into(), v6(2).into()));
    assert_eq!(
        (i.proto, i.first_proto, i.ttl, i.header_len, i.payload_len),
        (17, 17, 64, 40, 11)
    );
}

#[test]
fn extension_headers_are_walked_to_the_payload_protocol() {
    let mut chain = vec![60, 0, 1, 4, 0, 0, 0, 0];
    chain.extend_from_slice(&[17, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    chain.extend_from_slice(&udp_datagram((7, 8), b"x"));
    let pkt = ip6_packet(v6(1), v6(2), 0, &chain);
    let i = ip(parse(Net::Ipv6, &pkt, 0));
    assert_eq!((i.proto, i.first_proto), (17, 0));
    assert_eq!((i.header_len, i.payload_len, i.payload.len()), (64, 9, 9));
}

#[test]
fn ipv6_fragment_header_is_read() {
    let mut body = vec![17, 0, 0x00, 0x09, 0, 0, 0x12, 0x34];
    body.extend_from_slice(&[0; 8]);
    let pkt = ip6_packet(v6(1), v6(2), 44, &body);
    let i = ip(parse(Net::Ipv6, &pkt, 0));
    assert_eq!(i.proto, 17);
    assert_eq!(
        i.frag,
        Some(Frag {
            offset: 8,
            more: true,
            id: 0x1234
        })
    );
}

#[test]
fn truncated_ipv6_chains_stop_where_the_data_stops() {
    let pkt = ip6_packet(v6(1), v6(2), 0, &[6, 3, 0, 0]);
    let i = ip(parse(Net::Ipv6, &pkt, 0));
    assert_eq!((i.proto, i.header_len), (0, 40));
    assert!(i.payload.len() <= 4);
    assert_eq!(parse(Net::Ipv6, &pkt[..39], 0), NetLayer::Broken(Net::Ipv6));
}

#[test]
fn extension_header_loops_are_bounded() {
    let chain: Vec<u8> = std::iter::repeat_n([60u8, 0, 1, 4, 0, 0, 0, 0], 100)
        .flatten()
        .collect();
    let pkt = ip6_packet(v6(1), v6(2), 60, &chain);
    let i = ip(parse(Net::Ipv6, &pkt, 0));
    assert_eq!(i.header_len, 40 + 16 * 8);
}

#[test]
fn arp_over_ethernet_ipv4() {
    let frame = crate::test_util::arp_request(A, B);
    let NetLayer::Arp(a) = parse(Net::Arp, &frame, 14) else {
        panic!("not arp");
    };
    assert_eq!((a.op, a.sender_ip, a.target_ip), (1, A, B));
    assert_eq!(a.sender_mac, crate::test_util::MAC_A);
}

#[test]
fn other_arp_flavours_and_short_arp_are_broken() {
    let frame = crate::test_util::arp_request(A, B);
    for n in 14..frame.len() {
        assert_eq!(
            parse(Net::Arp, &frame[..n], 14),
            NetLayer::Broken(Net::Arp),
            "{n}"
        );
    }
    let mut ieee = frame.clone();
    ieee[15] = 6;
    assert_eq!(parse(Net::Arp, &ieee, 14), NetLayer::Broken(Net::Arp));
}

#[test]
fn unknown_network_protocols_have_no_layer() {
    assert_eq!(parse(Net::Other, &[1, 2, 3], 0), NetLayer::None);
}
