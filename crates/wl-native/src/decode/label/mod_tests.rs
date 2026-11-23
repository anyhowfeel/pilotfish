use std::net::{Ipv4Addr, Ipv6Addr};

use super::*;
use crate::decode::parse;
use crate::reader::LinkType;
use crate::test_util::*;

const A: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const B: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);

fn describe_frame(data: &[u8]) -> Label {
    let p = parse::packet(LinkType::Ethernet, data);
    describe(&p, None)
}

#[test]
fn udp_ports_pick_the_application_protocol() {
    let dns = udp4((A, 40000), (B, 53), &dns_query_payload(7, "example.com"));
    let l = describe_frame(&dns);
    assert_eq!(
        (l.protocol, l.info.as_str()),
        ("DNS", "Standard query 0x0007 A example.com")
    );
    let m = udp4(
        (A, 5353),
        (Ipv4Addr::new(224, 0, 0, 251), 5353),
        &dns_query_payload(0, "x.local"),
    );
    assert_eq!(describe_frame(&m).protocol, "MDNS");
}

#[test]
fn payloads_that_do_not_fit_the_port_fall_back_to_udp() {
    let l = describe_frame(&udp4((A, 40000), (B, 53), b"short"));
    assert_eq!(
        (l.protocol, l.info.as_str()),
        ("UDP", "40000 \u{2192} 53 Len=5")
    );
    assert_eq!(
        describe_frame(&udp4((A, 123), (B, 123), b"x")).protocol,
        "UDP"
    );
    assert_eq!(
        describe_frame(&udp4((A, 1), (B, 2), &[])).info,
        "1 \u{2192} 2 Len=0"
    );
}

#[test]
fn fragments_are_ipv4_with_the_fragment_note() {
    let first = eth_frame(
        0x0800,
        &ip4_packet(A, B, 17, 0xab, 0x2000, &udp_datagram((1, 2), &[0; 64])),
    );
    let l = describe_frame(&first);
    assert_eq!(
        (l.protocol, l.info.as_str()),
        (
            "IPv4",
            "Fragmented IP protocol (proto=UDP 17, off=0, ID=00ab)"
        )
    );
    let later = eth_frame(0x0800, &ip4_packet(A, B, 6, 0xab, 0x00b9, &[0; 8]));
    assert!(
        describe_frame(&later)
            .info
            .contains("proto=TCP 6, off=1480")
    );
}

#[test]
fn broken_and_unknown_layers_fall_back_to_the_deepest_one_understood() {
    assert_eq!(
        describe_frame(&eth_frame(0x0800, &[0x45, 0, 0])).protocol,
        "IPv4"
    );
    assert_eq!(
        describe_frame(&eth_frame(0x86dd, &[0x60; 10])).protocol,
        "IPv6"
    );
    assert_eq!(describe_frame(&eth_frame(0x0806, &[0; 10])).protocol, "ARP");
    assert_eq!(
        describe_frame(&eth_frame(0x88cc, &[0; 30])).protocol,
        "Ethernet"
    );
    assert_eq!(describe_frame(&[1, 2, 3]).protocol, "Ethernet");
    let raw = parse::packet(LinkType::Other(147), &[1, 2, 3]);
    assert_eq!(describe(&raw, None).protocol, "Raw");
}

#[test]
fn ip_protocols_without_a_decoder_are_named_by_ip_version() {
    let gre = eth_frame(0x0800, &ip4_packet(A, B, 47, 1, 0, &[0; 12]));
    assert_eq!(describe_frame(&gre).protocol, "IPv4");
    let v6 = eth_frame(
        0x86dd,
        &ip6_packet(Ipv6Addr::LOCALHOST, Ipv6Addr::LOCALHOST, 47, &[0; 12]),
    );
    assert_eq!(describe_frame(&v6).protocol, "IPv6");
}

#[test]
fn icmp_and_arp_dispatch() {
    assert_eq!(describe_frame(&icmp4_echo(A, B, 1, 1)).protocol, "ICMP");
    assert_eq!(describe_frame(&arp_request(A, B)).protocol, "ARP");
}
