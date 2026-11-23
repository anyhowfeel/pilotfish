use std::net::Ipv4Addr;

use super::*;
use crate::test_util::{SYN, eth_frame, icmp4_echo, ip4_packet, tcp4, udp_datagram, udp4};

const A: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const B: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);

#[test]
fn layers_stack_up_for_a_tcp_packet() {
    let data = tcp4((A, 1000), (B, 80), SYN, 1, 0, &[]);
    let p = packet(LinkType::Ethernet, &data);
    assert!(p.link.ethernet && p.ip().is_some());
    assert_eq!(p.ports(), Some((1000, 80)));
    assert_eq!(p.addrs(), Some((A.into(), B.into())));
    assert!(p.quoted.is_none());
}

#[test]
fn non_ip_packets_have_no_addresses_or_ports() {
    let data = eth_frame(0x88cc, &[0; 30]);
    let p = packet(LinkType::Ethernet, &data);
    assert_eq!((p.addrs(), p.ports()), (None, None));
}

fn unreachable_quoting(inner: &[u8]) -> Vec<u8> {
    let mut icmp = vec![3, 3, 0, 0, 0, 0, 0, 0];
    icmp.extend_from_slice(inner);
    eth_frame(0x0800, &ip4_packet(B, A, 1, 1, 0, &icmp))
}

#[test]
fn icmp_errors_expose_the_quoted_conversation() {
    let inner = ip4_packet(A, B, 17, 1, 0, &udp_datagram((4000, 5000), b"")[..8]);
    let data = unreachable_quoting(&inner);
    let p = packet(LinkType::Ethernet, &data);
    let q = p.quoted.expect("quoted");
    assert!(q.udp);
    assert_eq!((q.src, q.dst), ((A.into(), 4000), (B.into(), 5000)));
}

#[test]
fn quoted_tcp_needs_only_the_ports() {
    let tcp = crate::test_util::tcp_segment((1234, 80), 5, 0, 2, 1, &[], &[]);
    let inner = ip4_packet(A, B, 6, 1, 0, &tcp[..8]);
    let q = packet(LinkType::Ethernet, &unreachable_quoting(&inner))
        .quoted
        .expect("quoted");
    assert!(!q.udp);
    assert_eq!((q.src.1, q.dst.1), (1234, 80));
}

#[test]
fn unusable_quotes_are_ignored() {
    let cases = [
        unreachable_quoting(&[]),
        unreachable_quoting(&[0x45, 0, 0]),
        unreachable_quoting(&ip4_packet(A, B, 17, 1, 0, &[1, 2])),
        unreachable_quoting(&ip4_packet(A, B, 47, 1, 0, &[0; 8])),
        unreachable_quoting(&ip4_packet(A, B, 17, 1, 0x00b9, &[0; 8])),
        unreachable_quoting(&[0x15; 30]),
    ];
    for c in cases {
        assert!(packet(LinkType::Ethernet, &c).quoted.is_none());
    }
}

#[test]
fn echo_is_not_an_error_and_quotes_nothing() {
    let echo = icmp4_echo(A, B, 1, 1);
    let p = packet(LinkType::Ethernet, &echo);
    assert!(p.quoted.is_none() && p.ports().is_none());
    let datagram = udp4((A, 1), (B, 2), b"x");
    let u = packet(LinkType::Ethernet, &datagram);
    assert!(u.quoted.is_none());
}

fn quoted_tcp(kind: u8, keep: usize) -> Vec<u8> {
    let tcp = tcp4((A, 1000), (B, 80), SYN, 1, 0, &[]);
    let mut icmp = vec![kind, 1, 0, 0, 0, 0, 0, 0];
    icmp.extend_from_slice(&tcp[14..14 + 20 + keep]);
    eth_frame(0x0800, &ip4_packet(B, A, 1, 1, 0, &icmp))
}

#[test]
fn quoted_tcp_flags_need_fourteen_bytes_and_no_redirect() {
    let flags = |kind, keep| packet(LinkType::Ethernet, &quoted_tcp(kind, keep)).quoted_tcp_flags();
    assert_eq!(flags(3, 13), None);
    assert_eq!(flags(3, 14), Some(0x02));
    assert_eq!(flags(5, 20), None);
}
