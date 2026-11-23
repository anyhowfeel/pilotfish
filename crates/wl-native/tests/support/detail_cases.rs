//! Frames whose layer summary has a name of its own in Wireshark: ARP probes and gratuitous
//! messages (each sender keeps one MAC, so no duplicate-address analysis applies), the VLAN tag flavours and a datagram with the don't-fragment flag.

use std::net::Ipv4Addr;

use wl_native::test_util::*;

use super::conn::{A, B};
use super::synthetic::{Case, case};

fn arp(op: u16, sender: Ipv4Addr, target: Ipv4Addr, target_mac: [u8; 6]) -> Vec<u8> {
    let mut b = vec![0, 1, 8, 0, 6, 4];
    b.extend_from_slice(&op.to_be_bytes());
    b.extend_from_slice(&[2, 0, 0, 0, 0, sender.octets()[3]]);
    b.extend_from_slice(&sender.octets());
    b.extend_from_slice(&target_mac);
    b.extend_from_slice(&target.octets());
    eth_frame(0x0806, &b)
}

fn arp_kinds() -> Vec<Vec<u8>> {
    let (zero, mac) = ([0; 6], [2, 0, 0, 0, 0, 1]);
    vec![
        arp(1, A, B, zero),
        arp(1, Ipv4Addr::UNSPECIFIED, B, zero),
        arp(1, A, A, zero),
        arp(1, A, A, mac),
        arp(2, B, A, mac),
        arp(2, A, A, mac),
        arp(2, A, A, zero),
        arp(3, A, B, zero),
    ]
}

fn vlan_tags() -> Vec<Vec<u8>> {
    let ip = ip4_packet(A, B, 17, 1, 0x4000, &udp_datagram((5, 6), b"v"));
    let tagged = |tags: &[(u16, u16)]| eth_tagged(tags, 0x0800, &ip);
    vec![
        tagged(&[(0x88a8, 0x6007)]),
        tagged(&[(0x9100, 0x6007)]),
        tagged(&[(0x8100, 0xe007)]),
        tagged(&[(0x88a8, 7), (0x8100, 0x6008)]),
        tagged(&[(0x8100, 7), (0x8100, 8)]),
    ]
}

pub fn all() -> Vec<Case> {
    vec![
        case("detail-arp-kinds", arp_kinds()),
        case("detail-vlan-tags", vlan_tags()),
    ]
}
