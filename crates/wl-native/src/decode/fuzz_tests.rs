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

/// Deterministic xorshift, enough to pick bytes and lengths without a dependency.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

fn corpus() -> Vec<Vec<u8>> {
    let s6 = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    let tls = tls_record(22, 0x0301, &client_hello(0x0303, "fuzz.test", &[0x0304]));
    let mut v: Vec<Vec<u8>> = sample_frames().into_iter().map(|f| f.data).collect();
    v.extend([
        arp_request(A, B),
        tcp6((s6, 1), (s6, 2), SYN_ACK, 1, b"payload"),
        vlan_tcp4(5, (A, 1), (B, 2), b"GET / HTTP/1.1\r\n\r\n"),
        tcp4((A, 1), (B, 443), PSH_ACK, 1, 1, &tls),
        udp4((A, 1), (B, 53), &dns_response_payload(1, "a.test", B)),
        udp4((A, 68), (B, 67), &[1; 300]),
        udp4((A, 443), (B, 443), &[0xc3, 0, 0, 0, 1, 4, 1, 2, 3, 4, 0]),
        eth_tagged(
            &[(0x88a8, 1), (0x8100, 2)],
            0x86dd,
            &ip6_packet(
                s6,
                s6,
                58,
                &[
                    135, 0, 0, 0, 0, 0, 0, 0, 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                ],
            ),
        ),
    ]);
    v
}

#[test]
fn mutated_and_truncated_packets_never_panic() {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let mut d = Decoder::default();
    let links = [
        LinkType::Ethernet,
        LinkType::RawIp,
        LinkType::Null,
        LinkType::LinuxSll,
        LinkType::LinuxSll2,
    ];
    for base in corpus() {
        for round in 0..400 {
            let mut data = base.clone();
            match round % 4 {
                0 => data.truncate(rng.below(data.len() + 1)),
                1 => {
                    for _ in 0..1 + rng.below(4) {
                        let i = rng.below(data.len());
                        data[i] ^= 1 << rng.below(8);
                    }
                }
                2 => {
                    for _ in 0..1 + rng.below(8) {
                        let i = rng.below(data.len());
                        data[i] = rng.next() as u8;
                    }
                    data.truncate(rng.below(data.len() + 1));
                }
                _ => data = (0..rng.below(120)).map(|_| rng.next() as u8).collect(),
            }
            let m = PacketMeta {
                link: links[rng.below(links.len())],
                ..meta(round as u64 + 1, data.len())
            };
            let out = d.decode(&m, &data, 0.0);
            assert_eq!(out.row.len, data.len() as u32);
            assert!(!out.row.protocol.is_empty());
        }
    }
}

#[test]
fn single_byte_changes_in_the_header_region_never_panic() {
    let mut d = Decoder::default();
    for base in corpus() {
        for i in 0..base.len().min(80) {
            for v in [0u8, 0x7f, 0x80, 0xff] {
                let mut data = base.clone();
                data[i] = v;
                let _ = d.decode(&meta(1, data.len()), &data, 0.0);
            }
        }
    }
}
