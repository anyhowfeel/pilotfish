use super::eval_tests::{A, B, C, V6A, V6B, decode, matches, syn};
use crate::decode::Decoder;
use crate::reader::{LinkType, PacketMeta};
use crate::test_util::*;

#[test]
fn ports_follow_the_transport_that_carries_them() {
    let t = syn();
    let u = decode(&udp4((A, 5000), (B, 53), b"x"));
    for (filter, tcp, udp) in [
        ("tcp.port == 51000", true, false),
        ("tcp.port == 443", true, false),
        ("tcp.srcport == 51000", true, false),
        ("tcp.srcport == 443", false, false),
        ("tcp.dstport == 443", true, false),
        ("udp.port == 53", false, true),
        ("udp.srcport == 5000", false, true),
        ("udp.dstport == 5000", false, false),
        ("tcp.port != 80", true, false),
        ("udp.port != 80", false, true),
        ("tcp.port", true, false),
        ("udp.dstport", false, true),
        ("tcp.port in {80, 443}", true, false),
        ("udp.port in {53, 5353}", false, true),
        ("tcp.port in {1, 2}", false, false),
        ("tcp.port == 0x1bb", true, false),
    ] {
        assert_eq!(matches(filter, &t), tcp, "tcp: {filter}");
        assert_eq!(matches(filter, &u), udp, "udp: {filter}");
    }
}

#[test]
fn numbers_compare_in_every_direction() {
    let d = syn();
    for (filter, want) in [
        ("tcp.dstport == 443", true),
        ("tcp.dstport < 444", true),
        ("tcp.dstport < 443", false),
        ("tcp.dstport <= 443", true),
        ("tcp.dstport > 442", true),
        ("tcp.dstport > 443", false),
        ("tcp.dstport >= 443", true),
        ("tcp.dstport >= 444", false),
        ("tcp.srcport > 40000 && tcp.dstport < 1024", true),
        ("tcp.port > 50000", true),
        ("tcp.port > 60000", false),
        ("tcp.port < 100", false),
        ("tcp.port <= 443", true),
        ("tcp.port >= 51000", true),
    ] {
        assert_eq!(matches(filter, &d), want, "{filter}");
    }
}

#[test]
fn streams_frame_number_length_and_ip_header_fields() {
    let d = syn();
    let len = tcp4((A, 51000), (B, 443), SYN, 1, 0, &[]).len();
    assert!(matches("tcp.stream == 0", &d));
    assert!(matches("tcp.stream eq 0", &d));
    assert!(!matches("tcp.stream == 1", &d));
    assert!(matches("tcp.stream", &d));
    assert!(!matches("udp.stream", &d));
    assert!(matches("frame.number == 7", &d));
    assert!(matches("frame.number in {1, 7}", &d));
    assert!(!matches("frame.number > 7", &d));
    assert!(matches(&format!("frame.len == {len}"), &d));
    assert!(matches(&format!("frame.len >= {len}"), &d));
    assert!(!matches(&format!("frame.len > {len}"), &d));
    assert!(matches("ip.ttl == 64", &d));
    assert!(matches("ip.ttl < 65 && ip.ttl > 63", &d));
    assert!(matches("ip.proto == 6", &d));
    assert!(!matches("ip.proto == 17", &d));
    let u = decode(&udp4((A, 5000), (B, 53), b"x"));
    assert!(matches("udp.stream == 0", &u));
    assert!(!matches("tcp.stream", &u));
    assert!(matches("ip.proto == 17", &u));
    let v6 = decode(&tcp6((V6A, 1), (V6B, 2), SYN, 1, &[]));
    assert!(!matches("ip.ttl", &v6));
    assert!(!matches("ip.proto", &v6));
}

#[test]
fn streams_number_conversations_in_order() {
    let mut dec = Decoder::default();
    let mut next = |no: u64, f: Vec<u8>| {
        let meta = PacketMeta {
            no,
            epoch: 1.0,
            orig_len: f.len() as u32,
            link: LinkType::Ethernet,
        };
        dec.decode(&meta, &f, 1.0)
    };
    let one = next(1, tcp4((A, 1000), (B, 80), SYN, 1, 0, &[]));
    let two = next(2, tcp4((A, 1001), (B, 80), SYN, 1, 0, &[]));
    let back = next(3, tcp4((B, 80), (A, 1000), SYN_ACK, 1, 2, &[]));
    assert!(matches("tcp.stream == 0", &one) && matches("tcp.stream == 1", &two));
    assert!(matches("tcp.stream == 0", &back));
    assert!(matches("tcp.stream in {1, 7}", &two));
}

#[test]
fn tcp_flags_are_booleans() {
    let syn = syn();
    let synack = decode(&tcp4((B, 443), (A, 1), SYN_ACK, 1, 2, &[]));
    let ack = decode(&tcp4((A, 1), (B, 443), ACK, 1, 2, &[]));
    let pa = decode(&tcp4((A, 1), (B, 443), PSH_ACK, 1, 2, b"x"));
    let fin = decode(&tcp4((A, 1), (B, 443), FIN_ACK, 1, 2, &[]));
    let rst = decode(&tcp4((A, 1), (B, 443), RST, 1, 0, &[]));
    let udp = decode(&udp4((A, 5000), (B, 53), b"x"));
    let cases: [(&str, [bool; 7]); 12] = [
        (
            "tcp.flags.syn == 1",
            [true, true, false, false, false, false, false],
        ),
        (
            "tcp.flags.syn == true",
            [true, true, false, false, false, false, false],
        ),
        (
            "tcp.flags.syn == 0",
            [false, false, true, true, true, true, false],
        ),
        (
            "tcp.flags.syn == false",
            [false, false, true, true, true, true, false],
        ),
        (
            "tcp.flags.syn != 1",
            [false, false, true, true, true, true, false],
        ),
        ("tcp.flags.syn", [true, true, true, true, true, true, false]),
        (
            "tcp.flags.ack == 1",
            [false, true, true, true, true, false, false],
        ),
        (
            "tcp.flags.fin == 1",
            [false, false, false, false, true, false, false],
        ),
        (
            "tcp.flags.reset == 1",
            [false, false, false, false, false, true, false],
        ),
        (
            "tcp.flags.push == 1",
            [false, false, false, true, false, false, false],
        ),
        (
            "tcp.flags.syn == 1 && tcp.flags.ack == 0",
            [true, false, false, false, false, false, false],
        ),
        (
            "!(tcp.flags.syn == 1)",
            [false, false, true, true, true, true, true],
        ),
    ];
    for (filter, want) in cases {
        let got = [&syn, &synack, &ack, &pa, &fin, &rst, &udp].map(|d| matches(filter, d));
        assert_eq!(got, want, "{filter}");
    }
}

#[test]
fn ethernet_addresses() {
    let d = syn();
    let mac = |m: [u8; 6]| m.map(|b| format!("{b:02x}")).join(":");
    let (a, b) = (mac(MAC_A), mac(MAC_B));
    assert!(matches(&format!("eth.src == {a}"), &d));
    assert!(matches(&format!("eth.dst == {b}"), &d));
    assert!(matches(&format!("eth.addr == {a}"), &d));
    assert!(matches(&format!("eth.addr == {}", b.to_uppercase()), &d));
    assert!(!matches(&format!("eth.src == {b}"), &d));
    assert!(!matches(&format!("eth.addr != {a}"), &d));
    assert!(matches(
        &format!("eth.dst in {{ff:ff:ff:ff:ff:ff, {b}}}"),
        &d
    ));
    let bcast = decode(&arp_request(A, B));
    assert!(matches("eth.dst == ff:ff:ff:ff:ff:ff", &bcast));
    assert!(!matches("eth.dst != ff:ff:ff:ff:ff:ff", &bcast));
}

#[test]
fn an_icmp_error_also_holds_the_packet_it_quotes() {
    let inner = udp4((A, 41000), (C, 31001), b"x");
    let mut body = vec![3, 3, 0, 0, 0, 0, 0, 0];
    body.extend_from_slice(&inner[14..14 + 28]);
    let err = decode(&eth_frame(0x0800, &ip4_packet(B, A, 1, 1, 0, &body)));
    for (filter, want) in [
        ("icmp", true),
        ("udp", true),
        ("tcp", false),
        ("ip.src == 93.184.216.34", true),
        ("ip.src == 192.168.1.10", true),
        ("ip.dst == 10.1.2.3", true),
        ("ip.addr == 10.1.2.3", true),
        ("ip.addr != 10.1.2.3", false),
        ("ip.addr != 8.8.8.8", true),
        ("ip.addr == 192.168.1.10 && ip.addr == 10.1.2.3", true),
        ("udp.port == 41000", true),
        ("udp.dstport == 31001", true),
        ("udp.stream", true),
        ("ip.proto == 17 && ip.proto == 1", true),
        ("ip.ttl == 64", true),
        ("ip", true),
        ("ipv6", false),
    ] {
        assert_eq!(matches(filter, &err), want, "{filter}");
    }
}

#[test]
fn application_protocols_follow_the_protocol_column() {
    let dns = decode(&udp4((A, 5000), (B, 53), &dns_query_payload(1, "a.test")));
    let plain = decode(&udp4((A, 5000), (B, 9999), b"x"));
    assert!(matches("dns", &dns) && !matches("dns", &plain));
    assert!(matches("!dns", &plain));
    assert!(!matches("tls", &dns) && !matches("http", &dns));
    let hello = tls_record(22, 0x0301, &client_hello(0x0303, "example.test", &[0x1301]));
    let tls = decode(&tcp4((A, 40000), (B, 443), PSH_ACK, 1, 1, &hello));
    assert!(matches("tls", &tls) && matches("tcp && tls", &tls));
    assert!(!matches("tls", &syn()));
    let get = decode(&tcp4(
        (A, 40000),
        (B, 80),
        PSH_ACK,
        1,
        1,
        b"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
    ));
    assert!(matches("http", &get) && !matches("http", &syn()));
}
