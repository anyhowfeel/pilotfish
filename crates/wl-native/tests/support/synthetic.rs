//! Hand-built captures for the layouts the fixture files do not cover. Each is written to a pcap
//! so tshark reads exactly the bytes the decoder gets.

use std::net::{Ipv4Addr, Ipv6Addr};

use wl_native::test_util::*;

use super::conn::{A, ACK_F, B, Conn, FIN_F, PSH_F, RST_F, SYN_F, Seg};

pub struct Case {
    pub name: &'static str,
    pub frames: Vec<Frame>,
}

pub fn case(name: &'static str, packets: Vec<Vec<u8>>) -> Case {
    let frames = packets
        .into_iter()
        .enumerate()
        .map(|(i, p)| Frame::new(1_700_000_000.0 + i as f64 * 0.01, p))
        .collect();
    Case { name, frames }
}

fn tcp(
    from_a: bool,
    port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    opts: &[u8],
    data: &[u8],
) -> Vec<u8> {
    Seg::new(80, from_a, port, seq, ack, flags)
        .opts(opts)
        .data(data)
        .build()
}

fn arp(op: u16, smac: [u8; 6], sip: Ipv4Addr, tip: Ipv4Addr) -> Vec<u8> {
    let mut b = vec![0, 1, 8, 0, 6, 4];
    b.extend_from_slice(&op.to_be_bytes());
    b.extend_from_slice(&smac);
    b.extend_from_slice(&sip.octets());
    b.extend_from_slice(&[0; 6]);
    b.extend_from_slice(&tip.octets());
    eth_frame(0x0806, &b)
}

fn lifecycle() -> Vec<Vec<u8>> {
    let ws = [1, 3, 3, 7];
    let mut v = vec![
        tcp(true, 1111, 100, 0, SYN_F, &[2, 4, 5, 0xb4, 1, 3, 3, 7], &[]),
        tcp(
            false,
            1111,
            500,
            101,
            SYN_F | ACK_F,
            &[2, 4, 5, 0xb4, 1, 3, 3, 2],
            &[],
        ),
        tcp(true, 1111, 101, 501, ACK_F, &[], &[]),
        tcp(true, 1111, 101, 501, PSH_F | ACK_F, &[], b"hello"),
        tcp(false, 1111, 501, 106, ACK_F, &[], &[]),
        tcp(true, 1111, 106, 501, FIN_F | ACK_F, &[], &[]),
        tcp(false, 1111, 501, 107, FIN_F | ACK_F, &[], &[]),
        tcp(true, 1111, 107, 502, ACK_F, &[], &[]),
        tcp(true, 1111, 9000, 0, SYN_F, &[], &[]),
        tcp(false, 1111, 700, 9001, SYN_F | ACK_F, &[], &[]),
        tcp(true, 2222, 100, 0, SYN_F, &[], &[]),
        tcp(true, 2222, 100, 0, SYN_F, &[], &[]),
        tcp(true, 2222, 300, 0, SYN_F, &[], &[]),
        tcp(true, 3333, 100, 0, SYN_F, &[], &[]),
        tcp(false, 3333, 0, 101, RST_F | ACK_F, &[], &[]),
        tcp(true, 3333, 100, 0, SYN_F, &[], &[]),
        tcp(true, 4444, 5000, 9000, ACK_F, &[], b"abc"),
        tcp(false, 4444, 9000, 5003, ACK_F, &[], b"de"),
        tcp(true, 4444, 5003, 9002, ACK_F, &[], &[]),
        tcp(false, 5555, 100, 0, SYN_F | ACK_F, &ws, &[]),
        tcp(true, 5555, 7, 0, SYN_F, &[], &[]),
    ];
    v.push(tcp(true, 6666, u32::MAX - 1, 0, SYN_F, &[], &[]));
    v.push(tcp(true, 6666, 3, 0, ACK_F, &[], &[]));
    v
}

fn quoted_icmp() -> Vec<Vec<u8>> {
    let inner = udp4((A, 41000), (B, 31001), b"x");
    let mut icmp = vec![3, 3, 0, 0, 0, 0, 0, 0];
    icmp.extend_from_slice(&inner[14..14 + 28]);
    let err = eth_frame(0x0800, &ip4_packet(B, A, 1, 1, 0, &icmp));
    vec![err.clone(), inner, udp4((A, 6000), (B, 7000), b"y"), err]
}

fn ipv6() -> Vec<Vec<u8>> {
    let s = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let d = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 1, 0, 0, 2);
    let mapped = Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x0102, 0x0304);
    let udp6 =
        |src, dst, ports: (u16, u16), body: &[u8]| udp6((src, ports.0), (dst, ports.1), body);
    let mut hbh = vec![17, 0, 1, 4, 0, 0, 0, 0];
    hbh.extend_from_slice(&udp_datagram((7, 8), b"z"));
    let mut icmp_echo = vec![128, 0, 0, 0, 0, 1, 0, 2];
    icmp_echo.extend_from_slice(&[0; 8]);
    vec![
        tcp6((s, 1000), (d, 443), SYN, 1, &[]),
        udp6(s, d, (4000, 53), &dns_query_payload(3, "v6.test")),
        udp6(d, s, (53, 4000), &dns_response_payload(3, "v6.test", B)),
        udp6(s, mapped, (1, 2), b"m"),
        eth_frame(0x86dd, &ip6_packet(s, d, 0, &hbh)),
        eth_frame(0x86dd, &ip6_packet(s, d, 58, &icmp_echo)),
        udp6(Ipv6Addr::UNSPECIFIED, Ipv6Addr::LOCALHOST, (9, 9), b""),
        udp6(
            Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0, 1),
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 2),
            (9, 9),
            b"",
        ),
        udp6(
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 1, 2),
            Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 0),
            (9, 9),
            b"",
        ),
    ]
}

fn tls() -> Vec<Vec<u8>> {
    let mut flight = tls_record(22, 0x0303, &server_hello(0x0303, None));
    flight.extend(tls_record(22, 0x0303, &handshake_message(11, &[0, 0, 0])));
    flight.extend(tls_record(22, 0x0303, &handshake_message(14, &[])));
    let mut fin = tls_record(22, 0x0303, &handshake_message(16, &[0; 30]));
    fin.extend(tls_record(20, 0x0303, &[1]));
    fin.extend(tls_record(22, 0x0303, &[0; 40]));
    let mut a = Conn::open(7000, 9000);
    a.client(&tls_record(
        22,
        0x0301,
        &client_hello(0x0303, "a.test", &[0x0304, 0x0303]),
    ));
    a.server(&flight);
    a.client(&fin);
    a.server(&tls_record(23, 0x0303, &[1; 80]));
    a.client(&tls_record(21, 0x0303, &[0; 26]));
    let mut b = Conn::open(7001, 9000);
    b.client(&tls_record(
        22,
        0x0301,
        &client_hello(0x0303, "b.test", &[0x0304]),
    ));
    let mut hello13 = tls_record(22, 0x0303, &server_hello(0x0303, Some(0x0304)));
    hello13.extend(tls_record(20, 0x0303, &[1]));
    hello13.extend(tls_record(23, 0x0303, &[3; 50]));
    b.server(&hello13);
    b.server(&tls_record(23, 0x0303, &[4; 70]));
    b.client(&tls_record(23, 0x0303, &[5; 60]));
    a.out.extend(b.out);
    a.out
}

fn link_layers() -> Vec<Vec<u8>> {
    let udp = |ports| ip4_packet(A, B, 17, 1, 0, &udp_datagram(ports, b"v"));
    vec![
        vlan_tcp4(100, (A, 1), (B, 2), b"data"),
        eth_tagged(&[(0x88a8, 7), (0x8100, 8)], 0x0800, &udp((5, 6))),
        eth_tagged(
            &[(0x8100, 1), (0x8100, 2), (0x8100, 3)],
            0x0800,
            &udp((7, 8)),
        ),
        arp(1, MAC_A, A, B),
        arp(2, MAC_B, B, A),
        arp(1, MAC_A, A, A),
        arp(1, MAC_A, Ipv4Addr::UNSPECIFIED, B),
        eth_frame(0x0800, &ip4_packet(A, B, 47, 1, 0, &[0; 12])),
        udp4((A, 40000), (B, 53), &dns_query_payload(9, "x.test")),
        udp4((B, 53), (A, 40000), &dns_response_payload(9, "x.test", B)),
        udp4(
            (A, 5353),
            (Ipv4Addr::new(224, 0, 0, 251), 5353),
            &dns_query_payload(0, "_h._tcp.local"),
        ),
        udp4((A, 1), (B, 2), &[]),
        icmp4_echo(A, B, 7, 1),
    ]
}

fn fragments() -> Vec<Vec<u8>> {
    let d = udp_datagram((4000, 53), &dns_query_payload(1, "frag.test"));
    let f = |frag, part: &[u8]| eth_frame(0x0800, &ip4_packet(A, B, 17, 77, frag, part));
    vec![f(0x2000, &d[..16]), f(0x0002, &d[16..])]
}

pub fn all() -> Vec<Case> {
    let mut cases = vec![
        case("lifecycle", lifecycle()),
        case("icmp-quoted", quoted_icmp()),
        case("ipv6", ipv6()),
        case("tls", tls()),
        case("link-layers", link_layers()),
        case("fragments", fragments()),
    ];
    cases.extend(super::quote_cases::all());
    cases.extend(super::detail_cases::all());
    cases
}
