//! The TCP, UDP and ICMP nodes: wording and byte ranges.

use std::net::Ipv6Addr;

use super::layers_tests::{A, B, child, detail, has};
use crate::test_util::*;

#[test]
fn tcp_node_shows_flags_seq_ack_window_and_payload() {
    let f = tcp4((A, 51000), (B, 80), PSH_ACK, 1000, 2000, b"hello");
    let tcp = &detail(7, &f).layers[3];
    assert_eq!(
        tcp.label,
        "Transmission Control Protocol, Src Port: 51000, Dst Port: 80, Seq: 1000, Ack: 2000, Len: 5"
    );
    assert_eq!(tcp.range, Some((34, 54)));
    assert!(has(tcp, "Destination Port: 80"));
    assert_eq!(
        child(tcp, "Sequence Number (raw): 1000").range,
        Some((38, 42))
    );
    assert_eq!(
        child(tcp, "Acknowledgment Number (raw): 2000").range,
        Some((42, 46))
    );
    assert!(has(tcp, "Header Length: 20 bytes (5)"));
    assert_eq!(child(tcp, "Flags: 0x018 (PSH, ACK)").range, Some((47, 48)));
    assert_eq!(child(tcp, "Window: 64240").range, Some((48, 50)));
    assert_eq!(child(tcp, "TCP payload (5 bytes)").range, Some((54, 59)));
}

#[test]
fn syn_has_no_ack_in_its_title_or_children() {
    let f = tcp4((A, 1), (B, 2), SYN, 7, 0, &[]);
    let tcp = &detail(1, &f).layers[3];
    assert_eq!(
        tcp.label,
        "Transmission Control Protocol, Src Port: 1, Dst Port: 2, Seq: 7, Len: 0"
    );
    assert!(
        !tcp.children
            .iter()
            .any(|c| c.label.starts_with("Acknowledgment"))
    );
    assert!(has(tcp, "Flags: 0x002 (SYN)"));
}

#[test]
fn every_flag_is_named() {
    let f = tcp4_raw((A, 1), (B, 2), 1, 1, 0xff, &[], &[]);
    let tcp = &detail(1, &f).layers[3];
    assert!(has(
        tcp,
        "Flags: 0x0ff (FIN, SYN, RST, PSH, ACK, URG, ECE, CWR)"
    ));
}

#[test]
fn udp_node_shows_ports_length_and_payload() {
    let f = udp4((A, 40000), (B, 53), &dns_query_payload(1, "a.test"));
    let n = f.len() - 42;
    let udp = &detail(1, &f).layers[3];
    assert_eq!(
        udp.label,
        "User Datagram Protocol, Src Port: 40000, Dst Port: 53"
    );
    assert_eq!(udp.range, Some((34, 42)));
    assert!(has(udp, &format!("Length: {}", n + 8)));
    assert_eq!(
        child(udp, &format!("UDP payload ({n} bytes)")).range,
        Some((42, 42 + n))
    );
}

#[test]
fn dns_has_no_node_of_its_own() {
    let f = udp4((A, 40000), (B, 53), &dns_query_payload(1, "a.test"));
    assert_eq!(detail(1, &f).layers.len(), 4);
}

#[test]
fn icmp_echo_shows_identifier_and_sequence() {
    let f = icmp4_echo(A, B, 5, 9);
    let icmp = &detail(1, &f).layers[3];
    assert_eq!(icmp.label, "Internet Control Message Protocol");
    assert_eq!(icmp.range, Some((34, 38)));
    assert!(has(icmp, "Type: 8"));
    assert!(has(icmp, "Code: 0"));
    assert!(has(icmp, "Identifier: 5"));
    assert!(has(icmp, "Sequence Number: 9"));
}

#[test]
fn icmpv6_has_its_own_name() {
    let (s, d) = (Ipv6Addr::LOCALHOST, Ipv6Addr::LOCALHOST);
    let body = [128, 0, 0, 0, 0, 1, 0, 2, 0, 0];
    let f = eth_frame(0x86dd, &ip6_packet(s, d, 58, &body));
    let icmp = &detail(1, &f).layers[3];
    assert_eq!(icmp.label, "Internet Control Message Protocol v6");
    assert!(has(icmp, "Type: 128"));
    assert!(has(icmp, "Identifier: 1"));
}
