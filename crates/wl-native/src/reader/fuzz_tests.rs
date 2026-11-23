//! Damaged inputs must end in an error or a clean stop, never a panic or a hang.

use crate::test_util::{
    PcapStyle, ng_block, ng_epb, ng_idb, ng_shb, ng_spb, pcap_bytes, pcapng_bytes, sample_frames,
};

use super::ReadError;
use super::tests::drain_bytes;

struct Rng(u64);

impl Rng {
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

fn seeds() -> Vec<Vec<u8>> {
    let frames = sample_frames();
    let be_ng = [
        ng_shb(true),
        ng_idb(true, 1, 0, Some(9)),
        ng_epb(true, 0, 1_700_000_000_000_000_001, b"abcdef", 6),
        ng_block(4, &[0; 12], true),
        ng_spb(true, b"spb", 3),
        ng_shb(false),
        ng_idb(false, 113, 96, None),
        ng_epb(false, 0, 5, b"xyz", 90),
    ]
    .concat();
    vec![
        pcap_bytes(&frames, PcapStyle::default()),
        pcap_bytes(
            &frames,
            PcapStyle {
                nanos: true,
                big_endian: true,
                link_type: 113,
            },
        ),
        pcapng_bytes(&frames),
        be_ng,
    ]
}

fn mutate(rng: &mut Rng, seed: &[u8]) -> Vec<u8> {
    let mut b = seed.to_vec();
    for _ in 0..1 + rng.below(4) {
        let at = rng.below(b.len());
        match rng.below(5) {
            0 => b[at] ^= 1 << rng.below(8),
            1 => b[at] = rng.next() as u8,
            2 => {
                let word = [0u32, 0xffff_ffff, 0x7fff_ffff, 12, 1 << 24][rng.below(5)];
                for (i, byte) in word.to_le_bytes().iter().enumerate() {
                    if let Some(slot) = b.get_mut(at + i) {
                        *slot = *byte;
                    }
                }
            }
            3 => b.truncate(at),
            _ => {
                let end = (at + 1 + rng.below(32)).min(b.len());
                let chunk = b[at..end].to_vec();
                b.splice(at..at, chunk);
            }
        }
        if b.is_empty() {
            break;
        }
    }
    b
}

fn check(bytes: Vec<u8>) {
    let len = bytes.len();
    if let Ok(got) = drain_bytes(bytes) {
        assert!(got.packets.len() <= len);
        for (i, (meta, _)) in got.packets.iter().enumerate() {
            assert_eq!(meta.no, i as u64 + 1);
        }
        assert!(!matches!(got.error, Some(ReadError::Io(_))));
    }
}

#[test]
fn flipped_and_cut_bytes_never_panic() {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    for seed in seeds() {
        for _ in 0..3000 {
            check(mutate(&mut rng, &seed));
        }
    }
}

#[test]
fn every_prefix_of_a_valid_file_is_handled() {
    for seed in seeds() {
        let full = drain_bytes(seed.clone()).expect("seed").packets;
        for cut in 0..=seed.len() {
            match drain_bytes(seed[..cut].to_vec()) {
                Ok(got) => assert_eq!(got.packets, full[..got.packets.len()], "cut {cut}"),
                Err(e) if cut < 4 => assert_eq!(e, ReadError::UnknownFormat, "cut {cut}"),
                Err(e) => assert!(matches!(e, ReadError::Truncated(_)), "cut {cut}"),
            }
        }
    }
}

#[test]
fn random_bytes_after_a_valid_magic_never_panic() {
    let mut rng = Rng(42);
    for magic in [
        [0xd4, 0xc3, 0xb2, 0xa1],
        [0xa1, 0xb2, 0xc3, 0xd4],
        [0x4d, 0x3c, 0xb2, 0xa1],
        [0x0a, 0x0d, 0x0d, 0x0a],
    ] {
        for _ in 0..500 {
            let mut bytes = magic.to_vec();
            let n = rng.below(300);
            bytes.extend((0..n).map(|_| rng.next() as u8));
            check(bytes);
        }
    }
}
