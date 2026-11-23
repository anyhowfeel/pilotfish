use std::net::{Ipv4Addr, Ipv6Addr};

use super::*;
use crate::reader::LinkType;
use crate::test_util::*;

const A: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 10);
const B: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);

fn meta(no: u64, len: usize) -> PacketMeta {
    PacketMeta {
        no,
        epoch: 1_700_000_000.0 + no as f64,
        orig_len: len as u32,
        link: LinkType::Ethernet,
    }
}

fn run(frames: &[Vec<u8>]) -> Vec<Decoded> {
    let mut d = Decoder::default();
    frames
        .iter()
        .enumerate()
        .map(|(i, f)| d.decode(&meta(i as u64 + 1, f.len()), f, 1_700_000_001.0))
        .collect()
}

#[test]
fn a_tcp_packet_fills_every_row_field() {
    let f = tcp4((A, 51000), (B, 80), SYN, 100, 0, &[]);
    let d = &run(std::slice::from_ref(&f))[0];
    let r = &d.row;
    assert_eq!((r.no, r.len, r.stream), (1, f.len() as u32, Some(0)));
    assert_eq!((&*r.src, &*r.dst), ("192.168.1.10", "93.184.216.34"));
    assert_eq!((r.src_ip, r.dst_ip), (Some(A.into()), Some(B.into())));
    assert_eq!(
        (r.src_port, r.dst_port, r.transport),
        (Some(51000), Some(80), Transport::Tcp)
    );
    assert_eq!(&*r.protocol, "TCP");
    assert_eq!(&*r.info, "51000 \u{2192} 80 [SYN] Seq=0 Win=64240 Len=0");
    assert!(
        (r.rel - -0.0).abs() < 1e-9,
        "rel is epoch minus first_epoch"
    );
    assert_eq!(d.facts.tcp_flags, Some(0x02));
    assert_eq!(
        (d.facts.ip_version, d.facts.ip_proto, d.facts.ttl),
        (Some(4), Some(6), Some(64))
    );
    assert_eq!(
        (d.facts.eth_src, d.facts.eth_dst),
        (Some(MAC_A), Some(MAC_B))
    );
    assert_eq!(
        (d.facts.ethertype, d.facts.vlan, d.facts.stream),
        (Some(0x0800), None, Some(0))
    );
}

#[test]
fn the_sample_conversation_numbers_streams_and_labels_protocols() {
    let frames: Vec<Vec<u8>> = sample_frames().into_iter().map(|f| f.data).collect();
    let rows: Vec<_> = run(&frames).into_iter().map(|d| d.row).collect();
    let protocols: Vec<&str> = rows.iter().map(|r| &*r.protocol).collect();
    assert_eq!(
        protocols,
        ["DNS", "TCP", "TCP", "TCP", "HTTP", "TCP", "HTTP", "ICMP"]
    );
    let streams: Vec<_> = rows.iter().map(|r| r.stream).collect();
    assert_eq!(
        streams,
        [
            Some(0),
            Some(0),
            Some(0),
            Some(0),
            Some(0),
            Some(0),
            Some(0),
            None
        ]
    );
    assert_eq!(rows[7].transport, Transport::Icmp);
    assert_eq!(&*rows[5].info, "HTTP/1.1 200 OK ");
    assert_eq!(&*rows[6].info, "HTTP/1.1 200 OK ");
}

#[test]
fn rel_is_measured_from_the_first_epoch() {
    let f = udp4((A, 1), (B, 2), b"x");
    let mut d = Decoder::default();
    let m = PacketMeta {
        epoch: 12.5,
        ..meta(3, f.len())
    };
    assert!((d.decode(&m, &f, 10.0).row.rel - 2.5).abs() < 1e-12);
}

#[test]
fn interleaved_conversations_keep_their_own_streams() {
    let c = |p, s| tcp4((A, p), (B, 80), s, 1, 0, &[]);
    let r = |p| tcp4((B, 80), (A, p), ACK, 1, 1, &[]);
    let u = |p| udp4((A, p), (B, 53), &dns_query_payload(1, "a.test"));
    let rows = run(&[
        c(1, SYN),
        c(2, SYN),
        u(9),
        r(1),
        u(10),
        r(2),
        u(9),
        c(3, SYN),
    ]);
    let streams: Vec<_> = rows.iter().map(|d| d.row.stream.unwrap()).collect();
    assert_eq!(streams, [0, 1, 0, 0, 1, 1, 0, 2]);
}

#[test]
fn udp_len_is_the_wire_length_not_the_capture_length() {
    let f = udp4((A, 1), (B, 2), &[0; 200]);
    let mut d = Decoder::default();
    let m = PacketMeta {
        orig_len: 1514,
        ..meta(1, f.len())
    };
    let cut = &f[..60];
    let row = d.decode(&m, cut, 0.0).row;
    assert_eq!(row.len, 1514);
    assert_eq!((row.src_port, row.transport), (Some(1), Transport::Udp));
}

#[test]
fn arp_rows_use_mac_addresses() {
    let d = &run(&[arp_request(A, B)])[0];
    assert_eq!(
        (&*d.row.src, &*d.row.dst),
        ("02:00:00:00:00:0a", "ff:ff:ff:ff:ff:ff")
    );
    assert_eq!(
        (d.row.src_ip, d.row.stream, d.row.transport),
        (None, None, Transport::Other)
    );
    assert_eq!(&*d.row.protocol, "ARP");
    assert_eq!(&*d.row.info, "Who has 93.184.216.34? Tell 192.168.1.10");
}

#[test]
fn ipv6_rows_print_compressed_addresses() {
    let s = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let d = &run(&[tcp6((s, 1000), (Ipv6Addr::LOCALHOST, 443), SYN, 1, &[])])[0];
    assert_eq!((&*d.row.src, &*d.row.dst), ("2001:db8::1", "::1"));
    assert_eq!((d.facts.ip_version, d.row.stream), (Some(6), Some(0)));
}

#[test]
fn vlan_tagged_frames_report_the_id_and_the_inner_ethertype() {
    let f = vlan_tcp4(100, (A, 1), (B, 2), b"");
    let d = &run(&[f])[0];
    assert_eq!((d.facts.vlan, d.facts.ethertype), (Some(100), Some(0x0800)));
    assert_eq!(d.row.src_port, Some(1));
}

#[test]
fn stacked_vlan_tags_reach_the_ip_packet() {
    let ip = ip4_packet(A, B, 17, 1, 0, &udp_datagram((5, 6), b"x"));
    let f = eth_tagged(&[(0x88a8, 7), (0x8100, 8)], 0x0800, &ip);
    let d = &run(&[f])[0];
    assert_eq!(
        (d.facts.vlan, d.row.dst_port, &*d.row.protocol),
        (Some(7), Some(6), "UDP")
    );
}

#[test]
fn ipv6_with_extension_headers_and_no_ports_follows_the_base_header_for_transport() {
    let mut chain = vec![58, 0, 1, 4, 0, 0, 0, 0];
    chain.extend_from_slice(&[130, 0, 0, 0, 0, 0, 0, 0]);
    let f = eth_frame(
        0x86dd,
        &ip6_packet(Ipv6Addr::LOCALHOST, Ipv6Addr::LOCALHOST, 0, &chain),
    );
    let d = &run(&[f])[0];
    assert_eq!(
        (&*d.row.protocol, d.row.transport),
        ("ICMPv6", Transport::Other)
    );
    assert_eq!(d.facts.ip_proto, Some(58));
}

#[test]
fn fragments_carry_ports_on_the_first_one_only_and_no_stream() {
    let dgram = udp_datagram((4000, 5000), &[0; 40]);
    let first = eth_frame(0x0800, &ip4_packet(A, B, 17, 9, 0x2000, &dgram[..24]));
    let rest = eth_frame(0x0800, &ip4_packet(A, B, 17, 9, 0x0003, &dgram[24..]));
    let rows = run(&[first, rest]);
    assert_eq!(
        (rows[0].row.src_port, rows[0].row.stream),
        (Some(4000), None)
    );
    assert_eq!((rows[1].row.src_port, rows[1].row.stream), (None, None));
    assert_eq!(rows[1].row.transport, Transport::Udp);
}

#[test]
fn icmp_errors_take_ports_transport_and_stream_from_the_quoted_packet() {
    let q = udp4((A, 4000), (B, 5000), b"x");
    let inner = &q[14..14 + 28];
    let mut icmp = vec![3, 3, 0, 0, 0, 0, 0, 0];
    icmp.extend_from_slice(inner);
    let err = eth_frame(0x0800, &ip4_packet(B, A, 1, 1, 0, &icmp));
    let rows = run(&[q.clone(), err]);
    let r = &rows[1].row;
    assert_eq!(
        (r.src_port, r.dst_port, r.transport, r.stream),
        (Some(4000), Some(5000), Transport::Udp, Some(0))
    );
    assert_eq!((&*r.protocol, r.src_ip), ("ICMP", Some(B.into())));
}

#[test]
fn a_syn_on_a_finished_pair_starts_a_new_stream() {
    let p = |f, seq| tcp4((A, 1000), (B, 80), f, seq, 0, &[]);
    let rows = run(&[p(SYN, 100), p(FIN_ACK, 101), p(SYN, 100), p(SYN, 100)]);
    let streams: Vec<_> = rows.iter().map(|d| d.row.stream.unwrap()).collect();
    assert_eq!(streams, [0, 0, 1, 1]);
}

#[test]
fn empty_and_tiny_inputs_never_fail() {
    let mut d = Decoder::default();
    for n in 0..64 {
        let data = vec![0xffu8; n];
        for link in [
            LinkType::Ethernet,
            LinkType::Null,
            LinkType::RawIp,
            LinkType::LinuxSll,
            LinkType::LinuxSll2,
            LinkType::Other(9),
        ] {
            let m = PacketMeta { link, ..meta(1, n) };
            let out = d.decode(&m, &data, 0.0);
            assert_eq!(out.row.len, n as u32);
            assert!(!out.row.protocol.is_empty());
        }
    }
}

#[test]
fn non_ethernet_links_decode_their_network_layer() {
    let ip = ip4_packet(A, B, 17, 1, 0, &udp_datagram((7, 8), b"hi"));
    let mut d = Decoder::default();
    let raw = PacketMeta {
        link: LinkType::RawIp,
        ..meta(1, ip.len())
    };
    let r = d.decode(&raw, &ip, 0.0);
    assert_eq!(
        (r.row.src_port, &*r.row.protocol, r.facts.eth_src),
        (Some(7), "UDP", None)
    );
    let mut null = vec![2, 0, 0, 0];
    null.extend_from_slice(&ip);
    let m = PacketMeta {
        link: LinkType::Null,
        ..meta(2, null.len())
    };
    assert_eq!(d.decode(&m, &null, 0.0).row.dst_port, Some(8));
    let mut sll = vec![0, 0, 0, 1, 0, 6];
    sll.extend_from_slice(&MAC_A);
    sll.extend_from_slice(&[0, 0, 8, 0]);
    sll.extend_from_slice(&ip);
    let m = PacketMeta {
        link: LinkType::LinuxSll,
        ..meta(3, sll.len())
    };
    let r = d.decode(&m, &sll, 0.0);
    assert_eq!((r.row.dst_port, r.facts.eth_src), (Some(8), None));
}

#[test]
fn the_stream_table_is_bounded() {
    let mut d = Decoder {
        streams: StreamTable::with_capacity(8),
        ..Decoder::default()
    };
    for port in 1..100u16 {
        let f = udp4((A, port), (B, 53), b"x");
        d.decode(&meta(u64::from(port), f.len()), &f, 0.0);
    }
    assert_eq!(d.streams.len(), 8);
}

fn icmp_error(kind: u8, inner: &[u8], keep: usize) -> Vec<u8> {
    let mut icmp = vec![kind, 1, 0, 0, 0, 0, 0, 0];
    icmp.extend_from_slice(&inner[14..14 + 20 + keep]);
    eth_frame(0x0800, &ip4_packet(B, A, 1, 1, 0, &icmp))
}

#[test]
fn an_icmp_error_exposes_the_quoted_ip_header_and_tcp_flags() {
    let tcp = tcp4((A, 41000), (B, 80), SYN, 1, 0, &[]);
    let inner = |kind, keep| {
        let f = icmp_error(kind, &tcp, keep);
        run(&[f]).remove(0).facts.inner
    };
    let full = inner(3, 20).expect("quoted header");
    assert_eq!((full.src, full.dst), (A.into(), B.into()));
    assert_eq!((full.version, full.proto, full.ttl), (4, 6, 64));
    assert_eq!(full.tcp_flags, Some(0x02));
    assert_eq!(inner(3, 12).expect("quoted header").tcp_flags, None);
    assert_eq!(inner(5, 20).expect("quoted header").tcp_flags, None);
    assert_eq!(run(&[tcp]).remove(0).facts.inner, None);
}
