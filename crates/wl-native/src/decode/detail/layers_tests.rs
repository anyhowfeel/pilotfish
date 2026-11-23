//! The text and byte ranges of each layer node, against Wireshark's wording.

use std::net::{Ipv4Addr, Ipv6Addr};

use super::*;
use crate::reader::LinkType;
use crate::test_util::*;

pub(super) const A: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 10);
pub(super) const B: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);

pub(super) fn detail(no: u64, bytes: &[u8]) -> FrameDetail {
    let meta = PacketMeta {
        no,
        epoch: 1_700_000_000.5,
        orig_len: bytes.len() as u32,
        link: LinkType::Ethernet,
    };
    from_packet(&meta, bytes)
}

pub(super) fn child<'a>(layer: &'a DetailNode, label: &str) -> &'a DetailNode {
    layer
        .children
        .iter()
        .find(|c| c.label == label)
        .unwrap_or_else(|| panic!("no child {label:?} in {:?}", layer.children))
}

pub(super) fn has(layer: &DetailNode, label: &str) -> bool {
    layer.children.iter().any(|c| c.label == label)
}

#[test]
fn frame_node_follows_wiresharks_wording() {
    let f = tcp4((A, 1), (B, 2), SYN, 1, 0, &[b'x'; 20]);
    assert_eq!(f.len(), 74);
    let d = detail(5, &f);
    let frame = &d.layers[0];
    assert_eq!(
        frame.label,
        "Frame 5: 74 bytes on wire (592 bits), 74 bytes captured (592 bits)"
    );
    assert!(has(frame, "Frame Number: 5"));
    assert!(has(frame, "Frame Length: 74 bytes (592 bits)"));
    assert!(has(frame, "Capture Length: 74 bytes (592 bits)"));
    assert!(has(frame, "Epoch Arrival Time: 1700000000.500000000"));
    assert_eq!(frame.range, None);
}

#[test]
fn ethernet_node_lists_addresses_and_type() {
    let f = udp4((A, 1), (B, 2), b"");
    let eth = &detail(1, &f).layers[1];
    assert_eq!(
        eth.label,
        "Ethernet II, Src: 02:00:00:00:00:0a, Dst: 02:00:00:00:00:0b"
    );
    assert_eq!(eth.range, Some((0, 14)));
    assert_eq!(
        child(eth, "Destination: 02:00:00:00:00:0b").range,
        Some((0, 6))
    );
    assert_eq!(child(eth, "Source: 02:00:00:00:00:0a").range, Some((6, 12)));
    assert_eq!(child(eth, "Type: IPv4 (0x0800)").range, Some((12, 14)));
}

#[test]
fn vlan_tag_extends_the_ethernet_header() {
    let f = vlan_tcp4(100, (A, 1), (B, 2), b"");
    let eth = &detail(1, &f).layers[1];
    assert_eq!(eth.range, Some((0, 18)));
    let tag = child(eth, "802.1Q Virtual LAN, PRI: 0, DEI: 0, ID: 100");
    assert_eq!(tag.range, Some((14, 16)));
}

#[test]
fn provider_bridge_tags_use_the_802_1ad_name() {
    let ip = ip4_packet(A, B, 17, 1, 0, &udp_datagram((5, 6), b""));
    let f = eth_tagged(&[(0x88a8, 7), (0x8100, 0x6008)], 0x0800, &ip);
    let eth = &detail(1, &f).layers[1];
    assert!(has(eth, "IEEE 802.1ad, ID: 7"));
    assert!(has(eth, "802.1Q Virtual LAN, PRI: 3, DEI: 0, ID: 8"));
}

#[test]
fn ipv4_node_lists_the_header_fields() {
    let f = tcp4((A, 1), (B, 2), SYN, 1, 0, &[]);
    let ip = &detail(1, &f).layers[2];
    assert_eq!(
        ip.label,
        "Internet Protocol Version 4, Src: 192.168.1.10, Dst: 93.184.216.34"
    );
    assert_eq!(ip.range, Some((14, 34)));
    assert!(has(ip, "Header Length: 20 bytes (5)"));
    assert!(has(ip, "Total Length: 40"));
    assert!(has(ip, "Time to Live: 64"));
    assert!(has(ip, "Protocol: TCP (6)"));
    assert_eq!(
        child(ip, "Source Address: 192.168.1.10").range,
        Some((26, 30))
    );
    assert_eq!(
        child(ip, "Destination Address: 93.184.216.34").range,
        Some((30, 34))
    );
}

#[test]
fn ipv4_flags_and_fragment_offset_are_decoded() {
    let more = eth_frame(0x0800, &ip4_packet(A, B, 17, 9, 0x2000, &[0; 8]));
    assert!(has(
        &detail(1, &more).layers[2],
        "Flags: 0x1, More fragments"
    ));
    let last = eth_frame(0x0800, &ip4_packet(A, B, 17, 9, 0x4002, &[0; 8]));
    let ip = &detail(1, &last).layers[2];
    assert!(has(ip, "Flags: 0x2, Don't fragment"));
    assert!(has(ip, "Fragment Offset: 16"));
    assert!(has(ip, "Identification: 0x0009 (9)"));
}

#[test]
fn ipv6_node_lists_the_header_fields() {
    let (s, d) = (
        Ipv6Addr::LOCALHOST,
        Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 5),
    );
    let f = udp6((s, 1), (d, 2), b"abc");
    let ip = &detail(1, &f).layers[2];
    assert_eq!(
        ip.label,
        "Internet Protocol Version 6, Src: ::1, Dst: fe80::5"
    );
    assert_eq!(ip.range, Some((14, 54)));
    assert!(has(ip, "Payload Length: 11"));
    assert!(has(ip, "Next Header: UDP (17)"));
    assert!(has(ip, "Hop Limit: 64"));
    assert_eq!(child(ip, "Source Address: ::1").range, Some((22, 38)));
}

fn arp_frame(op: u16, sender: Ipv4Addr, target: Ipv4Addr, target_mac: [u8; 6]) -> Vec<u8> {
    let mut b = vec![0, 1, 8, 0, 6, 4];
    b.extend_from_slice(&op.to_be_bytes());
    b.extend_from_slice(&MAC_A);
    b.extend_from_slice(&sender.octets());
    b.extend_from_slice(&target_mac);
    b.extend_from_slice(&target.octets());
    eth_frame(0x0806, &b)
}

#[test]
fn arp_node_lists_the_addresses() {
    let f = arp_request(A, B);
    let arp = &detail(1, &f).layers[2];
    assert_eq!(arp.label, "Address Resolution Protocol (request)");
    assert_eq!(arp.range, Some((14, 42)));
    assert!(has(arp, "Opcode: request (1)"));
    assert_eq!(
        child(arp, "Sender IP address: 192.168.1.10").range,
        Some((28, 32))
    );
    assert_eq!(
        child(arp, "Target IP address: 93.184.216.34").range,
        Some((38, 42))
    );
    assert!(has(arp, "Sender MAC address: 02:00:00:00:00:0a"));
}

#[test]
fn arp_kinds_use_wiresharks_names() {
    let (z, m) = ([0; 6], MAC_B);
    let name = |f: Vec<u8>| detail(1, &f).layers[2].label.clone();
    let title = |kind: &str| format!("Address Resolution Protocol ({kind})");
    assert_eq!(name(arp_frame(2, B, A, m)), title("reply"));
    assert_eq!(
        name(arp_frame(1, Ipv4Addr::UNSPECIFIED, B, z)),
        title("ARP Probe")
    );
    assert_eq!(name(arp_frame(1, A, A, z)), title("ARP Announcement"));
    assert_eq!(name(arp_frame(1, A, A, m)), title("request/gratuitous ARP"));
    assert_eq!(name(arp_frame(2, A, A, m)), title("reply/gratuitous ARP"));
    assert_eq!(name(arp_frame(3, A, B, z)), title("reverse request"));
}

#[test]
fn a_fragment_has_no_transport_node() {
    let d = udp_datagram((4000, 53), &[0; 20]);
    let f = eth_frame(0x0800, &ip4_packet(A, B, 17, 77, 0x2000, &d[..16]));
    assert_eq!(detail(1, &f).layers.len(), 3);
}

#[test]
fn an_unknown_ethertype_stops_after_the_link_layer() {
    let d = detail(1, &eth_frame(0x88cc, &[0; 30]));
    assert_eq!(d.layers.len(), 2);
    assert!(has(&d.layers[1], "Type: Unknown (0x88cc)"));
}
