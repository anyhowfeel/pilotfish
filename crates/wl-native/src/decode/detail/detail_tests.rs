use std::net::Ipv4Addr;

use super::*;
use crate::reader::LinkType;
use crate::test_util::*;

const A: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 10);
const B: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);

fn meta(len: usize) -> PacketMeta {
    PacketMeta {
        no: 7,
        epoch: 1_700_000_000.25,
        orig_len: len as u32,
        link: LinkType::Ethernet,
    }
}

fn labels(d: &FrameDetail) -> Vec<&str> {
    d.layers.iter().map(|l| l.label.as_str()).collect()
}

fn all_ranges(n: &DetailNode, out: &mut Vec<(usize, usize)>) {
    out.extend(n.range);
    n.children.iter().for_each(|c| all_ranges(c, out));
}

#[test]
fn tcp_packet_has_frame_ethernet_ip_and_tcp_layers() {
    let f = tcp4((A, 51000), (B, 80), SYN, 100, 0, &[]);
    let d = from_packet(&meta(f.len()), &f);
    assert_eq!(d.frame_no, 7);
    assert_eq!(d.bytes, f);
    let l = labels(&d);
    assert_eq!(
        l[0],
        "Frame 7: 54 bytes on wire (432 bits), 54 bytes captured (432 bits)"
    );
    assert_eq!(
        l[1],
        "Ethernet II, Src: 02:00:00:00:00:0a, Dst: 02:00:00:00:00:0b"
    );
    assert_eq!(
        l[2],
        "Internet Protocol Version 4, Src: 192.168.1.10, Dst: 93.184.216.34"
    );
    assert_eq!(
        l[3],
        "Transmission Control Protocol, Src Port: 51000, Dst Port: 80, Seq: 100, Len: 0"
    );
    let tcp = &d.layers[3];
    assert!(tcp.children.iter().any(|c| c.label == "Flags: 0x002 (SYN)"));
    assert!(
        tcp.children
            .iter()
            .any(|c| c.label == "Source Port: 51000" && c.range == Some((34, 36)))
    );
}

#[test]
fn udp_icmp_and_arp_layers() {
    let u = udp4((A, 40000), (B, 53), &dns_query_payload(1, "a.test"));
    let d = from_packet(&meta(u.len()), &u);
    assert_eq!(
        labels(&d)[3],
        "User Datagram Protocol, Src Port: 40000, Dst Port: 53"
    );
    assert!(
        d.layers[3]
            .children
            .iter()
            .any(|c| c.label.starts_with("UDP payload"))
    );
    let i = icmp4_echo(A, B, 5, 9);
    let d = from_packet(&meta(i.len()), &i);
    assert_eq!(labels(&d)[3], "Internet Control Message Protocol");
    assert!(
        d.layers[3]
            .children
            .iter()
            .any(|c| c.label == "Sequence Number: 9")
    );
    let a = arp_request(A, B);
    let d = from_packet(&meta(a.len()), &a);
    assert_eq!(labels(&d)[2], "Address Resolution Protocol (request)");
    assert!(
        d.layers[2]
            .children
            .iter()
            .any(|c| c.label == "Sender IP address: 192.168.1.10")
    );
}

#[test]
fn vlan_tags_get_a_child_of_the_ethernet_node() {
    let f = vlan_tcp4(100, (A, 1), (B, 2), b"");
    let d = from_packet(&meta(f.len()), &f);
    assert!(
        d.layers[1]
            .children
            .iter()
            .any(|c| c.label.ends_with("ID: 100"))
    );
    assert!(
        d.layers[1]
            .children
            .iter()
            .any(|c| c.label == "Type: IPv4 (0x0800)")
    );
}

#[test]
fn ipv6_gets_its_own_node() {
    let s = std::net::Ipv6Addr::LOCALHOST;
    let f = tcp6((s, 1), (s, 2), SYN, 1, b"");
    let d = from_packet(&meta(f.len()), &f);
    assert_eq!(
        labels(&d)[2],
        "Internet Protocol Version 6, Src: ::1, Dst: ::1"
    );
}

#[test]
fn every_range_stays_inside_the_bytes_even_for_cut_packets() {
    let f = tcp4((A, 1), (B, 2), PSH_ACK, 1, 1, b"hello world");
    for n in 0..=f.len() {
        let d = from_packet(&meta(f.len()), &f[..n]);
        let mut ranges = Vec::new();
        d.layers.iter().for_each(|l| all_ranges(l, &mut ranges));
        assert!(ranges.iter().all(|(a, b)| a <= b && *b <= n), "{n}");
        assert_eq!(d.bytes.len(), n);
    }
}

#[test]
fn wire_length_can_exceed_the_captured_length() {
    let f = udp4((A, 1), (B, 2), b"x");
    let d = from_packet(
        &PacketMeta {
            orig_len: 1500,
            ..meta(f.len())
        },
        &f,
    );
    assert!(d.layers[0].label.starts_with("Frame 7: 1500 bytes on wire"));
    assert!(
        d.layers[0]
            .label
            .contains(&format!("{} bytes captured", f.len()))
    );
}

#[test]
fn garbage_gives_only_the_frame_layer_and_never_panics() {
    for n in 0..40 {
        let d = from_packet(&meta(n), &vec![0xee; n]);
        assert!(!d.layers.is_empty());
    }
    let d = from_packet(&meta(3), &[1, 2, 3]);
    assert_eq!(d.layers.len(), 1);
}

#[test]
fn mutated_packets_never_panic() {
    let f = tcp4((A, 1), (B, 2), PSH_ACK, 1, 1, b"hello world");
    for i in 0..f.len() {
        for v in [0u8, 0xff, 0x45] {
            let mut g = f.clone();
            g[i] = v;
            let _ = from_packet(&meta(g.len()), &g);
        }
    }
}
