use std::net::Ipv4Addr;

use super::*;
use crate::decode::parse;
use crate::decode::transport::Segment;
use crate::reader::LinkType;
use crate::test_util::{tcp4_raw, tls_record};

const A: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const B: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const SYN: u8 = 0x02;
const ACK: u8 = 0x10;
const PSH: u8 = 0x08;
const FIN: u8 = 0x01;
const RST: u8 = 0x04;

/// Feeds frames through the label code the way the decoder does, sharing one stream.
struct Flow {
    st: Stream,
}

impl Flow {
    fn new() -> Self {
        Flow { st: Stream::new(0) }
    }

    fn send(
        &mut self,
        from_a: bool,
        seq: u32,
        ack: u32,
        flags: u8,
        opts: &[u8],
        payload: &[u8],
    ) -> Label {
        let (src, dst) = if from_a {
            ((A, 40000), (B, 80))
        } else {
            ((B, 80), (A, 40000))
        };
        let frame = tcp4_raw(src, dst, seq, ack, flags, opts, payload);
        let pkt = parse::packet(LinkType::Ethernet, &frame);
        let (Some(ip), Segment::Tcp(t)) = (pkt.ip(), &pkt.segment) else {
            panic!("not tcp");
        };
        label(ip, t, Some((&mut self.st, usize::from(!from_a))))
    }
}

#[test]
fn handshake_uses_relative_numbers_and_options() {
    let mut f = Flow::new();
    let syn_opts = [
        2, 4, 5, 0xb4, 4, 2, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0, 1, 3, 3, 7,
    ];
    let l = f.send(true, 1000, 0, SYN, &syn_opts, &[]);
    assert_eq!(l.protocol, "TCP");
    assert_eq!(
        l.info,
        "40000 \u{2192} 80 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM TSval=1 TSecr=0 WS=128"
    );
    let l = f.send(false, 5000, 1001, SYN | ACK, &[2, 4, 5, 0xb4], &[]);
    assert_eq!(
        l.info,
        "80 \u{2192} 40000 [SYN, ACK] Seq=0 Ack=1 Win=64240 Len=0 MSS=1460"
    );
    let l = f.send(true, 1001, 5001, ACK, &[], &[]);
    assert_eq!(
        l.info,
        "40000 \u{2192} 80 [ACK] Seq=1 Ack=1 Win=64240 Len=0"
    );
    let l = f.send(true, 1001, 5001, PSH | ACK, &[], b"xyz");
    assert_eq!(
        l.info,
        "40000 \u{2192} 80 [PSH, ACK] Seq=1 Ack=1 Win=64240 Len=3"
    );
    let l = f.send(false, 5001, 1004, FIN | ACK, &[], &[]);
    assert_eq!(
        l.info,
        "80 \u{2192} 40000 [FIN, ACK] Seq=1 Ack=4 Win=64240 Len=0"
    );
}

#[test]
fn the_window_is_scaled_only_when_both_sides_announced_a_shift() {
    let mut f = Flow::new();
    f.send(true, 0, 0, SYN, &[1, 3, 3, 4], &[]);
    assert!(
        f.send(false, 0, 1, SYN | ACK, &[], &[])
            .info
            .contains("Win=64240 ")
    );
    assert!(
        f.send(true, 1, 1, ACK, &[], &[])
            .info
            .contains("Win=64240 ")
    );
    let mut g = Flow::new();
    g.send(true, 0, 0, SYN, &[1, 3, 3, 4], &[]);
    g.send(false, 0, 1, SYN | ACK, &[1, 3, 3, 2], &[]);
    assert!(
        g.send(true, 1, 1, ACK, &[], &[])
            .info
            .contains(&format!("Win={}", 64240 << 4))
    );
    assert!(
        g.send(false, 1, 1, ACK, &[], &[])
            .info
            .contains(&format!("Win={}", 64240 << 2))
    );
}

#[test]
fn a_stream_joined_late_counts_from_the_packet_before_the_first() {
    let mut f = Flow::new();
    let l = f.send(true, 5000, 9000, ACK, &[], b"abc");
    assert_eq!(
        l.info,
        "40000 \u{2192} 80 [ACK] Seq=1 Ack=1 Win=64240 Len=3"
    );
    let l = f.send(false, 9000, 5003, ACK, &[], b"de");
    assert_eq!(
        l.info,
        "80 \u{2192} 40000 [ACK] Seq=1 Ack=4 Win=64240 Len=2"
    );
    let l = f.send(true, 5003, 9002, ACK, &[], &[]);
    assert!(l.info.contains("Seq=4 Ack=3"));
}

#[test]
fn rst_without_ack_omits_the_ack_field_and_no_flags_say_none() {
    let mut f = Flow::new();
    f.send(true, 100, 0, SYN, &[], &[]);
    assert_eq!(
        f.send(true, 101, 0, RST, &[], &[]).info,
        "40000 \u{2192} 80 [RST] Seq=1 Win=64240 Len=0"
    );
    assert!(f.send(true, 101, 0, 0, &[], &[]).info.contains("[<None>]"));
    assert!(f.st.closed);
}

#[test]
fn sequence_numbers_wrap() {
    let mut f = Flow::new();
    f.send(true, u32::MAX - 1, 0, SYN, &[], &[]);
    let l = f.send(true, 3, 0, ACK, &[], &[]);
    assert!(l.info.contains("Seq=5 "), "{}", l.info);
}

#[test]
fn sack_blocks_are_relative_to_the_peer() {
    let mut f = Flow::new();
    f.send(true, 100, 0, SYN, &[], &[]);
    f.send(false, 900, 101, SYN | ACK, &[], &[]);
    let mut sack = vec![1, 1, 5, 10];
    sack.extend_from_slice(&1001u32.to_be_bytes());
    sack.extend_from_slice(&1101u32.to_be_bytes());
    let l = f.send(true, 101, 901, ACK, &sack, &[]);
    assert!(l.info.ends_with(" SLE=101 SRE=201"), "{}", l.info);
}

#[test]
fn unknown_and_broken_options_are_skipped() {
    let mut f = Flow::new();
    let l = f.send(true, 1, 0, SYN, &[30, 4, 1, 1, 2, 4, 5, 0xb4], &[]);
    assert!(l.info.ends_with("Len=0 MSS=1460"));
    let l = f.send(true, 1, 0, SYN, &[2, 1, 0, 0], &[]);
    assert!(l.info.ends_with("Len=0"));
    let l = f.send(true, 1, 0, SYN, &[2, 40, 0, 0], &[]);
    assert!(l.info.ends_with("Len=0"));
}

#[test]
fn tls_and_http_payloads_take_over_the_label() {
    let mut f = Flow::new();
    f.send(true, 0, 0, SYN, &[], &[]);
    let hello = tls_record(
        22,
        0x0301,
        &crate::test_util::client_hello(0x0303, "x.test", &[]),
    );
    let l = f.send(true, 1, 1, PSH | ACK, &[], &hello);
    assert_eq!(
        (l.protocol, l.info.as_str()),
        ("TLSv1.2", "Client Hello (SNI=x.test)")
    );
    let mut g = Flow::new();
    let l = g.send(
        true,
        1,
        1,
        PSH | ACK,
        &[],
        b"GET /x HTTP/1.1\r\nHost: a\r\n\r\n",
    );
    assert_eq!((l.protocol, l.info.as_str()), ("HTTP", "GET /x HTTP/1.1 "));
}

#[test]
fn unrecognised_payloads_stay_tcp() {
    let mut f = Flow::new();
    let l = f.send(true, 1, 1, PSH | ACK, &[], b"\x00\x01binary");
    assert_eq!(l.protocol, "TCP");
    assert!(l.info.ends_with("Len=8"));
}

#[test]
fn tls_record_split_over_segments_gets_the_reassembly_note() {
    let mut f = Flow::new();
    let rec = tls_record(23, 0x0303, &[1; 3000]);
    let l = f.send(false, 1, 1, ACK, &[], &rec[..1400]);
    assert_eq!(l.protocol, "TCP");
    assert!(
        l.info
            .ends_with("Len=1400 [TCP segment of a reassembled PDU]")
    );
    let l = f.send(false, 1401, 1, ACK, &[], &rec[1400..]);
    assert_eq!(
        (l.protocol, l.info.as_str()),
        ("TLSv1.2", "Application Data")
    );
}

#[test]
fn a_tuple_free_call_does_not_panic() {
    let frame = tcp4_raw((A, 1), (B, 2), 1, 1, ACK, &[], b"x");
    let pkt = parse::packet(LinkType::Ethernet, &frame);
    let (Some(ip), Segment::Tcp(t)) = (pkt.ip(), &pkt.segment) else {
        panic!("not tcp");
    };
    assert_eq!(label(ip, t, None).protocol, "TCP");
}
