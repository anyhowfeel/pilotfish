//! Whole packets built with etherparse: the common cases a test needs.

use std::net::{Ipv4Addr, Ipv6Addr};

use etherparse::PacketBuilder;

use super::{MAC_A, MAC_B};

/// TCP flags a test can set.
#[derive(Debug, Clone, Copy, Default)]
pub struct Flags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    pub psh: bool,
}

pub const SYN: Flags = Flags {
    syn: true,
    ack: false,
    fin: false,
    rst: false,
    psh: false,
};
pub const SYN_ACK: Flags = Flags {
    syn: true,
    ack: true,
    fin: false,
    rst: false,
    psh: false,
};
pub const ACK: Flags = Flags {
    syn: false,
    ack: true,
    fin: false,
    rst: false,
    psh: false,
};
pub const PSH_ACK: Flags = Flags {
    syn: false,
    ack: true,
    fin: false,
    rst: false,
    psh: true,
};
pub const FIN_ACK: Flags = Flags {
    syn: false,
    ack: true,
    fin: true,
    rst: false,
    psh: false,
};
pub const RST: Flags = Flags {
    syn: false,
    ack: false,
    fin: false,
    rst: true,
    psh: false,
};

/// Ethernet + IPv4 + TCP.
pub fn tcp4(
    src: (Ipv4Addr, u16),
    dst: (Ipv4Addr, u16),
    flags: Flags,
    seq: u32,
    ack: u32,
    payload: &[u8],
) -> Vec<u8> {
    let mut b = PacketBuilder::ethernet2(MAC_A, MAC_B)
        .ipv4(src.0.octets(), dst.0.octets(), 64)
        .tcp(src.1, dst.1, seq, 64240);
    if flags.syn {
        b = b.syn();
    }
    if flags.ack {
        b = b.ack(ack);
    }
    if flags.fin {
        b = b.fin();
    }
    if flags.rst {
        b = b.rst();
    }
    if flags.psh {
        b = b.psh();
    }
    let mut out = Vec::new();
    b.write(&mut out, payload).expect("tcp4 packet");
    out
}

/// Ethernet + IPv6 + TCP.
pub fn tcp6(
    src: (Ipv6Addr, u16),
    dst: (Ipv6Addr, u16),
    flags: Flags,
    seq: u32,
    payload: &[u8],
) -> Vec<u8> {
    let mut b = PacketBuilder::ethernet2(MAC_A, MAC_B)
        .ipv6(src.0.octets(), dst.0.octets(), 64)
        .tcp(src.1, dst.1, seq, 64240);
    if flags.syn {
        b = b.syn();
    }
    if flags.ack {
        b = b.ack(1);
    }
    let mut out = Vec::new();
    b.write(&mut out, payload).expect("tcp6 packet");
    out
}

/// Ethernet + 802.1Q + IPv4 + TCP.
pub fn vlan_tcp4(vlan: u16, src: (Ipv4Addr, u16), dst: (Ipv4Addr, u16), payload: &[u8]) -> Vec<u8> {
    let b = PacketBuilder::ethernet2(MAC_A, MAC_B)
        .single_vlan(etherparse::VlanId::try_new(vlan).expect("vlan id"))
        .ipv4(src.0.octets(), dst.0.octets(), 64)
        .tcp(src.1, dst.1, 1, 1000);
    let mut out = Vec::new();
    b.write(&mut out, payload).expect("vlan packet");
    out
}

/// Ethernet + IPv4 + UDP.
pub fn udp4(src: (Ipv4Addr, u16), dst: (Ipv4Addr, u16), payload: &[u8]) -> Vec<u8> {
    let b = PacketBuilder::ethernet2(MAC_A, MAC_B)
        .ipv4(src.0.octets(), dst.0.octets(), 64)
        .udp(src.1, dst.1);
    let mut out = Vec::new();
    b.write(&mut out, payload).expect("udp4 packet");
    out
}

/// Ethernet + IPv4 + ICMP echo request.
pub fn icmp4_echo(src: Ipv4Addr, dst: Ipv4Addr, id: u16, seq: u16) -> Vec<u8> {
    let b = PacketBuilder::ethernet2(MAC_A, MAC_B)
        .ipv4(src.octets(), dst.octets(), 64)
        .icmpv4_echo_request(id, seq);
    let mut out = Vec::new();
    b.write(&mut out, &[0; 8]).expect("icmp packet");
    out
}

/// Ethernet frame with an ARP request, the one non-IP packet the tests need.
pub fn arp_request(sender: Ipv4Addr, target: Ipv4Addr) -> Vec<u8> {
    let mut out = Vec::with_capacity(42);
    out.extend_from_slice(&[0xff; 6]);
    out.extend_from_slice(&MAC_A);
    out.extend_from_slice(&[0x08, 0x06, 0, 1, 8, 0, 6, 4, 0, 1]);
    out.extend_from_slice(&MAC_A);
    out.extend_from_slice(&sender.octets());
    out.extend_from_slice(&[0; 6]);
    out.extend_from_slice(&target.octets());
    out
}

/// A DNS message header plus one question for `name`, type A, class IN.
pub fn dns_query_payload(id: u16, name: &str) -> Vec<u8> {
    let mut out = vec![(id >> 8) as u8, id as u8, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.extend_from_slice(&[0, 0, 1, 0, 1]);
    out
}

/// Ethernet + IPv6 + UDP, with valid checksums.
pub fn udp6(src: (Ipv6Addr, u16), dst: (Ipv6Addr, u16), payload: &[u8]) -> Vec<u8> {
    let b = PacketBuilder::ethernet2(MAC_A, MAC_B)
        .ipv6(src.0.octets(), dst.0.octets(), 64)
        .udp(src.1, dst.1);
    let mut out = Vec::new();
    b.write(&mut out, payload).expect("udp6 packet");
    out
}
