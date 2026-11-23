//! Captures that only the filter test needs: ICMP errors, which Wireshark shows with a second IP
//! layer, and TCP flag and TTL variety.

use std::net::{Ipv4Addr, Ipv6Addr};

use wl_native::test_util::*;

use super::conn::{A, B};
use super::synthetic::Case;

const R: Ipv4Addr = Ipv4Addr::new(10, 9, 9, 9);

fn case(name: &'static str, packets: Vec<Vec<u8>>) -> Case {
    let frames = packets
        .into_iter()
        .enumerate()
        .map(|(i, p)| Frame::new(1_700_000_000.0 + i as f64 * 0.01, p))
        .collect();
    Case { name, frames }
}

/// An ICMP error from `from` to `to` that quotes the IP header of `inner` and `keep` bytes more.
fn icmp_error(from: Ipv4Addr, to: Ipv4Addr, kind: u8, inner: &[u8], keep: usize) -> Vec<u8> {
    let mut icmp = vec![kind, 1, 0, 0, 0, 0, 0, 0];
    icmp.extend_from_slice(&inner[14..14 + 20 + keep]);
    eth_frame(0x0800, &ip4_packet(from, to, 1, 1, 0, &icmp))
}

fn icmp_errors() -> Vec<Vec<u8>> {
    let tcp = tcp4((A, 41000), (B, 80), SYN, 1, 0, &[]);
    let udp = udp4((A, 41000), (B, 53), b"x");
    let echo = icmp4_echo(A, B, 3, 4);
    let mut v = vec![tcp.clone(), udp.clone(), echo.clone()];
    for keep in [8, 12, 14, 16, 20] {
        v.push(icmp_error(R, A, 3, &tcp, keep));
    }
    v.push(icmp_error(R, A, 11, &udp, 8));
    v.push(icmp_error(B, A, 3, &echo, 8));
    v.push(icmp_error(R, A, 5, &tcp, 20));
    v
}

fn icmpv6_error() -> Vec<Vec<u8>> {
    let (s, d) = (
        Ipv6Addr::LOCALHOST,
        Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 5),
    );
    let udp = udp_datagram((41214, 19998), b"abcd");
    let mut body = vec![1, 4, 0, 0, 0, 0, 0, 0];
    body.extend_from_slice(&ip6_packet(s, d, 17, &udp));
    vec![
        eth_frame(0x86dd, &ip6_packet(d, s, 58, &body)),
        eth_frame(0x86dd, &ip6_packet(s, d, 17, &udp)),
    ]
}

fn tcp_variety() -> Vec<Vec<u8>> {
    let raw = |flags, ports| {
        eth_frame(
            0x0800,
            &ip4_packet(
                A,
                B,
                6,
                1,
                0,
                &tcp_segment(ports, 1, 1, flags, 1000, &[], &[]),
            ),
        )
    };
    let mut v: Vec<Vec<u8>> = [
        0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x11, 0x12, 0x14, 0x18, 0x29, 0x3f,
    ]
    .into_iter()
    .map(|f| raw(f, (1000 + u16::from(f), 80)))
    .collect();
    v.push(tcp6(
        (Ipv6Addr::LOCALHOST, 7),
        (Ipv6Addr::LOCALHOST, 8),
        SYN_ACK,
        1,
        &[],
    ));
    v.push(udp4((A, 9), (B, 9), &[]));
    v
}

pub fn all() -> Vec<Case> {
    vec![
        case("filter-icmp-errors", icmp_errors()),
        case("filter-icmpv6-error", icmpv6_error()),
        case("filter-tcp-variety", tcp_variety()),
    ]
}
