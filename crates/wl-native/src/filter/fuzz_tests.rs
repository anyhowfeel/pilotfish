//! Deterministic mutation fuzzing: no filter text, however broken, may panic, and a filter that
//! parses must evaluate on any packet.

use super::parse;
use crate::decode::Decoder;
use crate::reader::{LinkType, PacketMeta};
use crate::test_util::*;
use std::net::Ipv4Addr;

struct Xorshift(u64);

impl Xorshift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

const SEEDS: &[&str] = &[
    "tcp",
    "!tcp && udp || icmp",
    "ip.addr == 10.0.0.0/8 && tcp.port in {80, 443}",
    "ipv6.addr != fe80::1 or not (eth.dst == ff:ff:ff:ff:ff:ff)",
    "frame.number >= 10 && frame.len lt 0x400",
    "tcp.flags.syn == 1 && tcp.flags.ack == false",
    "ip.ttl == 100 || udp.stream eq 3",
    "((tcp.port == 80))",
];

const PIECES: &[&str] = &[
    "(",
    ")",
    "{",
    "}",
    ",",
    "!",
    "!=",
    "==",
    "&&",
    "||",
    "<",
    ">=",
    "and",
    "or",
    "not",
    "in",
    "eq",
    "tcp",
    "ip.addr",
    "10.0.0.1",
    "10.0.0.0/8",
    "::1",
    "ff:ff:ff:ff:ff:ff",
    "0x",
    "80",
    "99999999999999999999",
    "/",
    ":",
    ".",
    "\"",
    "[",
    "\0",
    "é",
    "-",
    "  ",
];

fn mutate(rng: &mut Xorshift, seed: &str) -> String {
    let mut chars: Vec<char> = seed.chars().collect();
    for _ in 0..=rng.below(4) {
        let at = rng.below(chars.len() + 1);
        match rng.below(4) {
            0 if at < chars.len() => {
                chars.remove(at);
            }
            1 => {
                let piece = PIECES[rng.below(PIECES.len())];
                chars.splice(at..at, piece.chars());
            }
            2 if at < chars.len() => chars[at] = char::from(32 + rng.below(95) as u8),
            _ => chars.truncate(at),
        }
    }
    chars.into_iter().collect()
}

fn packets() -> Vec<crate::decode::Decoded> {
    let a = Ipv4Addr::new(10, 0, 0, 1);
    let b = Ipv4Addr::new(10, 0, 0, 2);
    let frames = [
        tcp4((a, 1), (b, 80), SYN, 1, 0, &[]),
        udp4((a, 5), (b, 53), b"x"),
        arp_request(a, b),
        vec![0xff; 3],
    ];
    let mut dec = Decoder::default();
    frames
        .iter()
        .enumerate()
        .map(|(i, f)| {
            let meta = PacketMeta {
                no: i as u64 + 1,
                epoch: 1.0,
                orig_len: f.len() as u32,
                link: LinkType::Ethernet,
            };
            dec.decode(&meta, f, 1.0)
        })
        .collect()
}

#[test]
fn mutated_filters_never_panic() {
    let mut rng = Xorshift(0x9e37_79b9_7f4a_7c15);
    let pkts = packets();
    let mut parsed = 0;
    for _ in 0..20_000 {
        let seed = SEEDS[rng.below(SEEDS.len())];
        let text = mutate(&mut rng, seed);
        if let Some(f) = parse(&text) {
            parsed += 1;
            for p in &pkts {
                let _ = f.matches(p);
            }
        }
    }
    assert!(parsed > 500, "only {parsed} mutants still parse");
}

#[test]
fn random_bytes_never_panic() {
    let mut rng = Xorshift(0x1234_5678_9abc_def1);
    for _ in 0..5_000 {
        let len = rng.below(64);
        let text: String = (0..len)
            .map(|_| char::from_u32(rng.below(0x250) as u32).unwrap_or('?'))
            .collect();
        let _ = parse(&text);
    }
}

#[test]
fn every_prefix_of_a_filter_is_handled() {
    for seed in SEEDS {
        for end in 0..=seed.len() {
            if seed.is_char_boundary(end) {
                let _ = parse(&seed[..end]);
            }
        }
    }
}
