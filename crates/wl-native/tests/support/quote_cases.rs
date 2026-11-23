//! ICMP errors that open the capture, before any connection exists, so a number the decoder gives
//! to a quoted packet shifts every later stream. Wireshark numbers a quoted TCP conversation only
//! when the quote reaches the flags byte of the TCP header, and never for an ICMP redirect.

use std::net::{Ipv4Addr, Ipv6Addr};

use wl_native::test_util::*;

use super::conn::{A, B};
use super::synthetic::{Case, case};

const R: Ipv4Addr = Ipv4Addr::new(10, 9, 9, 9);
const V6A: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
const V6B: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);

/// An ICMP error of `kind` from the router that quotes the IP header of `inner` and `keep` more.
fn error4(kind: u8, inner: &[u8], keep: usize) -> Vec<u8> {
    let mut icmp = vec![kind, 1, 0, 0, 0, 0, 0, 0];
    icmp.extend_from_slice(&inner[14..14 + 20 + keep]);
    eth_frame(0x0800, &ip4_packet(R, A, 1, 1, 0, &icmp))
}

fn error6(kind: u8, inner: &[u8], keep: usize) -> Vec<u8> {
    let mut icmp = vec![kind, 1, 0, 0, 0, 0, 0, 0];
    icmp.extend_from_slice(&inner[14..14 + 40 + keep]);
    eth_frame(0x86dd, &ip6_packet(V6B, V6A, 58, &icmp))
}

fn short_quotes() -> Vec<Vec<u8>> {
    let syn = |port| tcp4((A, port), (B, 80), SYN, 1, 0, &[]);
    let udp = udp4((A, 50000), (B, 5000), b"x");
    let syn6 = |port| tcp6((V6A, port), (V6B, 80), SYN, 1, &[]);
    vec![
        error4(3, &syn(40000), 8),
        error4(3, &syn(40001), 12),
        error4(3, &syn(40002), 13),
        error4(3, &syn(40003), 14),
        error4(5, &syn(40004), 20),
        error4(11, &udp, 8),
        error4(5, &udp, 8),
        error4(3, &udp, 2),
        error6(1, &syn6(40005), 8),
        error6(1, &syn6(40006), 14),
        syn(40000),
        syn(40001),
        syn(40002),
        syn(40003),
        syn(40004),
        udp,
        syn6(40005),
        syn6(40006),
        tcp4((A, 40007), (B, 80), SYN, 1, 0, &[]),
    ]
}

pub fn all() -> Vec<Case> {
    vec![case("icmp-short-quotes", short_quotes())]
}
