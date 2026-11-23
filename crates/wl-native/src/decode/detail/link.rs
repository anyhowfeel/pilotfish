use wl_model::DetailNode;

use super::{field, node};
use crate::decode::fmt;
use crate::decode::net::Arp;
use crate::decode::parse::Packet;
use crate::decode::read::be16;
use crate::reader::LinkType;

const PROVIDER_BRIDGE: u16 = 0x88a8;

fn ethertype_name(t: u16) -> &'static str {
    match t {
        0x0800 => "IPv4",
        0x86dd => "IPv6",
        0x0806 => "ARP",
        _ => "Unknown",
    }
}

fn header_name(link: LinkType) -> &'static str {
    match link {
        LinkType::RawIp => "Raw packet data",
        LinkType::Null => "Null/Loopback",
        LinkType::LinuxSll => "Linux cooked capture v1",
        LinkType::LinuxSll2 => "Linux cooked capture v2",
        _ => "Link layer header",
    }
}

fn vlan_label(tpid: Option<u16>, tci: u16) -> String {
    if tpid == Some(PROVIDER_BRIDGE) {
        return format!("IEEE 802.1ad, ID: {}", tci & 0x0fff);
    }
    format!(
        "802.1Q Virtual LAN, PRI: {}, DEI: {}, ID: {}",
        tci >> 13,
        tci >> 12 & 1,
        tci & 0x0fff
    )
}

pub fn link(link: LinkType, pkt: &Packet, bytes: &[u8]) -> Option<DetailNode> {
    let l = &pkt.link;
    if !l.ethernet {
        let range = (l.offset > 0).then_some((0, l.offset.min(bytes.len())));
        return l
            .complete
            .then(|| node(header_name(link).into(), range, vec![]));
    }
    let (src, dst) = (fmt::mac(&l.src?), fmt::mac(&l.dst?));
    let total = bytes.len();
    let mut children = vec![
        field(format!("Destination: {dst}"), 0, 6, total),
        field(format!("Source: {src}"), 6, 6, total),
    ];
    let mut at = 12;
    while at + 4 <= l.offset
        && let Some(tci) = be16(bytes, at + 2)
    {
        children.push(field(vlan_label(be16(bytes, at), tci), at + 2, 2, total));
        at += 4;
    }
    if let Some(ty) = l.ethertype {
        children.push(field(
            format!("Type: {} (0x{ty:04x})", ethertype_name(ty)),
            at,
            2,
            total,
        ));
    }
    Some(node(
        format!("Ethernet II, Src: {src}, Dst: {dst}"),
        Some((0, l.offset.min(total))),
        children,
    ))
}

/// Wireshark's name for probes, announcements and gratuitous messages.
fn arp_kind(a: &Arp, op: &str) -> String {
    let gratuitous = a.sender_ip == a.target_ip;
    match a.op {
        1 if a.sender_ip.is_unspecified() => "ARP Probe".into(),
        1 if gratuitous && a.target_mac == [0; 6] => "ARP Announcement".into(),
        1 | 2 if gratuitous => format!("{op}/gratuitous ARP"),
        3 => "reverse request".into(),
        4 => "reverse reply".into(),
        _ => op.into(),
    }
}

pub fn arp(a: &Arp, at: usize, t: usize) -> DetailNode {
    let op = match a.op {
        1 => "request",
        2 => "reply",
        _ => "unknown",
    };
    node(
        format!("Address Resolution Protocol ({})", arp_kind(a, op)),
        Some((at, at + 28)),
        vec![
            field("Hardware type: Ethernet (1)".into(), at, 2, t),
            field("Protocol type: IPv4 (0x0800)".into(), at + 2, 2, t),
            field("Hardware size: 6".into(), at + 4, 1, t),
            field("Protocol size: 4".into(), at + 5, 1, t),
            field(format!("Opcode: {op} ({})", a.op), at + 6, 2, t),
            field(
                format!("Sender MAC address: {}", fmt::mac(&a.sender_mac)),
                at + 8,
                6,
                t,
            ),
            field(format!("Sender IP address: {}", a.sender_ip), at + 14, 4, t),
            field(
                format!("Target MAC address: {}", fmt::mac(&a.target_mac)),
                at + 18,
                6,
                t,
            ),
            field(format!("Target IP address: {}", a.target_ip), at + 24, 4, t),
        ],
    )
}
