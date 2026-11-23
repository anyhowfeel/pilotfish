use std::net::{Ipv4Addr, Ipv6Addr};

use super::parse;
use crate::decode::{Decoded, Decoder};
use crate::reader::{LinkType, PacketMeta};
use crate::test_util::*;

pub(super) const A: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 10);
pub(super) const B: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);
pub(super) const C: Ipv4Addr = Ipv4Addr::new(10, 1, 2, 3);
pub(super) const V6A: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
pub(super) const V6B: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);

pub(super) fn decode(frame: &[u8]) -> Decoded {
    let meta = PacketMeta {
        no: 7,
        epoch: 1_700_000_000.0,
        orig_len: frame.len() as u32,
        link: LinkType::Ethernet,
    };
    Decoder::default().decode(&meta, frame, 1_700_000_000.0)
}

pub(super) fn matches(filter: &str, d: &Decoded) -> bool {
    parse(filter)
        .unwrap_or_else(|| panic!("{filter} parses"))
        .matches(d)
}

pub(super) fn syn() -> Decoded {
    decode(&tcp4((A, 51000), (B, 443), SYN, 1, 0, &[]))
}

#[test]
fn protocol_presence() {
    let tcp = syn();
    let udp = decode(&udp4((A, 5000), (B, 53), b"x"));
    let icmp = decode(&icmp4_echo(A, B, 1, 1));
    let arp = decode(&arp_request(A, B));
    let v6 = decode(&tcp6((V6A, 1), (V6B, 2), SYN, 1, &[]));
    let table: [(&str, [bool; 5]); 8] = [
        ("tcp", [true, false, false, false, true]),
        ("udp", [false, true, false, false, false]),
        ("icmp", [false, false, true, false, false]),
        ("arp", [false, false, false, true, false]),
        ("ip", [true, true, true, false, false]),
        ("ipv6", [false, false, false, false, true]),
        ("eth", [true; 5]),
        ("icmpv6", [false; 5]),
    ];
    for (filter, want) in table {
        let got = [&tcp, &udp, &icmp, &arp, &v6].map(|d| matches(filter, d));
        assert_eq!(got, want, "{filter}");
    }
}

#[test]
fn ipv4_addresses_match_either_end() {
    let d = syn();
    assert!(matches("ip.addr == 192.168.1.10", &d));
    assert!(matches("ip.addr == 93.184.216.34", &d));
    assert!(!matches("ip.addr == 10.1.2.3", &d));
    assert!(matches("ip.src == 192.168.1.10", &d));
    assert!(!matches("ip.src == 93.184.216.34", &d));
    assert!(matches("ip.dst == 93.184.216.34", &d));
    assert!(!matches("ip.dst == 192.168.1.10", &d));
}

#[test]
fn not_equal_means_no_occurrence_equals() {
    let d = syn();
    assert!(!matches("ip.addr != 192.168.1.10", &d));
    assert!(!matches("ip.addr != 93.184.216.34", &d));
    assert!(matches("ip.addr != 10.1.2.3", &d));
    assert!(matches("ip.src != 93.184.216.34", &d));
    assert!(!matches("ip.src != 192.168.1.10", &d));
}

#[test]
fn not_equal_on_an_absent_field_is_false_but_negated_equal_is_true() {
    let arp = decode(&arp_request(A, B));
    assert!(!matches("ip.addr == 192.168.1.10", &arp));
    assert!(!matches("ip.addr != 192.168.1.10", &arp));
    assert!(matches("!(ip.addr == 192.168.1.10)", &arp));
    assert!(matches("!ip.addr == 192.168.1.10", &arp));
    assert!(!matches("tcp.port != 80", &arp));
    assert!(!matches("tcp.flags.syn != 1", &arp));
    assert!(!matches("frame.number != 7", &arp));
    assert!(!matches(
        "eth.addr != 00:00:00:00:00:00",
        &decode(&[1, 2, 3])
    ));
}

#[test]
fn each_side_of_an_and_binds_on_its_own() {
    let d = syn();
    assert!(matches(
        "ip.addr == 192.168.1.10 && ip.addr == 93.184.216.34",
        &d
    ));
    assert!(matches(
        "ip.addr == 93.184.216.34 && ip.addr == 192.168.1.10",
        &d
    ));
    assert!(matches(
        "ip.addr == 192.168.1.10 && ip.addr == 192.168.1.10",
        &d
    ));
    assert!(!matches(
        "ip.addr == 192.168.1.10 && ip.addr == 10.1.2.3",
        &d
    ));
    assert!(matches("tcp.port == 51000 && tcp.port == 443", &d));
    assert!(matches("tcp.port == 443 && tcp.port == 443", &d));
    assert!(!matches("tcp.port == 443 && tcp.port == 80", &d));
    assert!(matches(
        "ip.addr == 192.168.1.10 && ip.addr != 10.1.2.3",
        &d
    ));
}

#[test]
fn cidr_masks_the_address() {
    let d = syn();
    for (filter, want) in [
        ("ip.addr == 192.168.0.0/16", true),
        ("ip.addr == 192.168.1.0/24", true),
        ("ip.addr == 192.168.2.0/24", false),
        ("ip.addr == 192.168.1.10/32", true),
        ("ip.addr == 192.168.1.11/32", false),
        ("ip.addr == 192.168.1.11/31", true),
        ("ip.addr == 192.168.1.12/31", false),
        ("ip.addr == 0.0.0.0/0", true),
        ("ip.addr == 255.255.255.255/0", true),
        ("ip.addr == 192.168.1.99/16", true),
        ("ip.src == 93.0.0.0/8", false),
        ("ip.dst == 93.0.0.0/8", true),
        ("ip.src != 93.0.0.0/8", true),
        ("ip.addr != 0.0.0.0/0", false),
        ("ip.addr == 128.0.0.0/1", true),
        ("ip.addr == 10.0.0.0/8", false),
    ] {
        assert_eq!(matches(filter, &d), want, "{filter}");
    }
}

#[test]
fn ipv6_addresses_and_prefixes() {
    let d = decode(&tcp6((V6A, 1000), (V6B, 80), SYN, 1, &[]));
    for (filter, want) in [
        ("ipv6.addr == 2001:db8::1", true),
        ("ipv6.addr == 2001:0db8:0:0:0:0:0:1", true),
        ("ipv6.addr == fe80::2", true),
        ("ipv6.src == 2001:db8::1", true),
        ("ipv6.src == fe80::2", false),
        ("ipv6.dst == fe80::2", true),
        ("ipv6.addr == 2001:db8::/32", true),
        ("ipv6.addr == 2001:db9::/32", false),
        ("ipv6.addr == fe80::/10", true),
        ("ipv6.addr == ::/0", true),
        ("ipv6.addr == 2001:db8::1/128", true),
        ("ipv6.addr == 2001:db8::2/128", false),
        ("ipv6.addr == 2001:db8::ffff/64", true),
        ("ipv6.addr != 2001:db8::1", false),
        ("ipv6.addr != ::1", true),
        ("ip.addr == 192.168.1.10", false),
        ("ip", false),
        ("ipv6", true),
    ] {
        assert_eq!(matches(filter, &d), want, "{filter}");
    }
    assert!(!matches("ipv6.addr == 2001:db8::1", &syn()));
}

#[test]
fn boolean_combinations() {
    let d = syn();
    for (filter, want) in [
        ("tcp && ip", true),
        ("tcp && udp", false),
        ("tcp || udp", true),
        ("!tcp", false),
        ("not udp", true),
        ("!(tcp && udp)", true),
        ("!tcp || ip", true),
        ("udp && tcp || ip", true),
        ("udp && (tcp || ip)", false),
        ("ip.addr == 10.1.2.3 || tcp.port == 443", true),
        ("ip.addr == 10.1.2.3 or tcp.port == 80", false),
        ("tcp.port == 443 and ip.addr == 192.168.1.10", true),
    ] {
        assert_eq!(matches(filter, &d), want, "{filter}");
    }
}

#[test]
fn ip_sets_match_any_member_and_prefix() {
    let d = syn();
    assert!(matches("ip.addr in {10.1.2.3, 93.184.216.34}", &d));
    assert!(!matches("ip.addr in {10.1.2.3}", &d));
    assert!(matches(
        "ip.addr in {10.1.2.3}",
        &decode(&tcp4((C, 1), (B, 2), SYN, 1, 0, &[]))
    ));
    assert!(matches("ip.addr in {10.0.0.0/8, 192.168.0.0/16}", &d));
    assert!(!matches("ip.addr in {10.0.0.0/8}", &d));
    assert!(matches(
        "ip.src in {192.168.1.10} && ip.dst in {93.184.216.34}",
        &d
    ));
    assert!(!matches("ip.src in {93.184.216.34}", &d));
}

#[test]
fn bytes_that_are_not_a_packet_still_evaluate() {
    let d = decode(&[]);
    for f in [
        "tcp",
        "ip",
        "eth",
        "ip.addr == 1.1.1.1",
        "tcp.port == 80",
        "!ip",
    ] {
        let _ = matches(f, &d);
    }
    assert!(matches("!ip", &d));
}
