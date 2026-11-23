use std::net::Ipv4Addr;

use super::*;
use crate::decode::link::Net;
use crate::decode::net::{self, NetLayer};
use crate::test_util::{ip4_packet, tcp_segment, udp_datagram};

const A: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const B: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);

fn segment_of(pkt: &[u8]) -> Segment<'_> {
    let NetLayer::Ip(ip) = net::parse(Net::Ipv4, pkt, 0) else {
        panic!("no ip");
    };
    parse(&ip)
}

#[test]
fn tcp_header_flags_options_and_payload() {
    let tcp = tcp_segment((51000, 80), 7, 9, 0x1b, 512, &[2, 4, 5, 0xb4], b"data");
    let pkt = ip4_packet(A, B, 6, 1, 0, &tcp);
    let Segment::Tcp(t) = segment_of(&pkt) else {
        panic!("not tcp");
    };
    assert_eq!(
        (t.src, t.dst, t.seq, t.ack, t.window),
        (51000, 80, 7, 9, 512)
    );
    assert_eq!(t.flags, 0x1b);
    assert!(t.has(Tcp::SYN) && t.has(Tcp::ACK) && !t.has(Tcp::RST));
    assert_eq!(
        (t.header_len, t.options, t.payload),
        (24, &[2u8, 4, 5, 0xb4][..], &b"data"[..])
    );
    assert_eq!((t.offset, t.payload_len), (20, 4));
}

#[test]
fn tcp_payload_length_is_the_declared_one_when_the_capture_is_cut() {
    let tcp = tcp_segment((1, 2), 0, 0, 0x10, 1, &[], &[0; 1000]);
    let pkt = ip4_packet(A, B, 6, 1, 0, &tcp);
    let Segment::Tcp(t) = segment_of(&pkt[..100]) else {
        panic!("not tcp");
    };
    assert_eq!((t.payload_len, t.payload.len()), (1000, 60));
}

#[test]
fn short_or_inconsistent_tcp_headers_are_not_segments() {
    let tcp = tcp_segment((1, 2), 0, 0, 0x10, 1, &[], &[]);
    let pkt = ip4_packet(A, B, 6, 1, 0, &tcp);
    for n in 20..40 {
        assert_eq!(segment_of(&pkt[..n]), Segment::None, "{n}");
    }
    let mut bad_offset = tcp.clone();
    bad_offset[12] = 0x30;
    assert_eq!(
        segment_of(&ip4_packet(A, B, 6, 1, 0, &bad_offset)),
        Segment::None
    );
}

#[test]
fn udp_header_and_length() {
    let pkt = ip4_packet(A, B, 17, 1, 0, &udp_datagram((53, 4000), b"hello"));
    let Segment::Udp(u) = segment_of(&pkt) else {
        panic!("not udp");
    };
    assert_eq!(
        (u.src, u.dst, u.length, u.payload),
        (53, 4000, 13, &b"hello"[..])
    );
}

#[test]
fn udp_length_field_cuts_the_payload() {
    let mut d = udp_datagram((1, 2), b"hello world");
    d[4..6].copy_from_slice(&10u16.to_be_bytes());
    let pkt = ip4_packet(A, B, 17, 1, 0, &d);
    let Segment::Udp(u) = segment_of(&pkt) else {
        panic!("not udp");
    };
    assert_eq!(u.payload, b"he");
    d[4..6].copy_from_slice(&3u16.to_be_bytes());
    let pkt = ip4_packet(A, B, 17, 1, 0, &d);
    let Segment::Udp(u) = segment_of(&pkt) else {
        panic!("not udp");
    };
    assert!(u.payload.is_empty());
}

#[test]
fn icmp_type_code_and_body() {
    let pkt = ip4_packet(A, B, 1, 1, 0, &[8, 0, 0, 0, 0, 1, 0, 2]);
    let Segment::Icmp(i) = segment_of(&pkt) else {
        panic!("not icmp");
    };
    assert_eq!(
        (i.v6, i.kind, i.code, i.body),
        (false, 8, 0, &[0u8, 1, 0, 2][..])
    );
    assert_eq!(
        segment_of(&ip4_packet(A, B, 1, 1, 0, &[8, 0, 0])),
        Segment::None
    );
}

#[test]
fn later_fragments_and_unknown_protocols_have_no_segment() {
    let tcp = tcp_segment((1, 2), 0, 0, 0x10, 1, &[], &[]);
    assert_eq!(
        segment_of(&ip4_packet(A, B, 6, 1, 0x00b9, &tcp)),
        Segment::None
    );
    assert!(matches!(
        segment_of(&ip4_packet(A, B, 6, 1, 0x2000, &tcp)),
        Segment::Tcp(_)
    ));
    assert_eq!(
        segment_of(&ip4_packet(A, B, 47, 1, 0, &[0; 8])),
        Segment::None
    );
}
