//! Reading stays within a bounded buffer whatever the file size.

use std::io::Read;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::test_util::{ng_epb, ng_idb, ng_shb};

use super::fill::IoErrors;
use super::pcap::PcapSource;
use super::pcapng::PcapngSource;
use super::stream::{INITIAL_BUFFER, MAX_BLOCK};
use super::{PacketSource, ReadError};

const PACKETS: u64 = 200_000;

/// A file made on demand: `head`, then `count` records, then `tail`. Nothing of it is stored.
struct Generated {
    head: Vec<u8>,
    record: fn(u64) -> Vec<u8>,
    count: u64,
    tail: u64,
    pending: Vec<u8>,
    next: u64,
    largest_read: Arc<AtomicUsize>,
}

impl Read for Generated {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.largest_read.fetch_max(buf.len(), Ordering::Relaxed);
        let mut filled = 0;
        while filled < buf.len() {
            if self.pending.is_empty() {
                if !self.head.is_empty() {
                    self.pending = std::mem::take(&mut self.head);
                } else if self.next < self.count {
                    self.pending = (self.record)(self.next);
                    self.next += 1;
                } else if self.tail > 0 {
                    let n = self.tail.min(64 * 1024);
                    self.pending = vec![0; n as usize];
                    self.tail -= n;
                } else {
                    break;
                }
                self.pending.reverse();
            }
            while filled < buf.len() {
                let Some(b) = self.pending.pop() else { break };
                buf[filled] = b;
                filled += 1;
            }
        }
        Ok(filled)
    }
}

fn generated(
    head: Vec<u8>,
    record: fn(u64) -> Vec<u8>,
    count: u64,
    tail: u64,
) -> (Generated, Arc<AtomicUsize>) {
    let largest = Arc::new(AtomicUsize::new(0));
    let g = Generated {
        head,
        record,
        count,
        tail,
        pending: Vec::new(),
        next: 0,
        largest_read: Arc::clone(&largest),
    };
    (g, largest)
}

fn pcap_header() -> Vec<u8> {
    let mut h = 0xa1b2_c3d4u32.to_le_bytes().to_vec();
    h.extend_from_slice(&[
        2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0, 0, 0,
    ]);
    h
}

fn pcap_record(i: u64) -> Vec<u8> {
    let mut r = Vec::new();
    for v in [(i / 1000) as u32, (i % 1000) as u32, 60, 60] {
        r.extend_from_slice(&v.to_le_bytes());
    }
    r.extend_from_slice(&[i as u8; 60]);
    r
}

fn ng_record(i: u64) -> Vec<u8> {
    ng_epb(false, 0, i * 1000, &[i as u8; 60], 60)
}

fn count_all(source: &mut dyn PacketSource) -> (u64, Option<ReadError>) {
    let mut data = Vec::new();
    let mut seen = 0;
    let mut last_epoch = -1.0;
    loop {
        match source.next_packet(&mut data) {
            Ok(Some(meta)) => {
                seen += 1;
                assert_eq!(meta.no, seen);
                assert!(meta.epoch > last_epoch);
                assert_eq!(data.len(), 60);
                last_epoch = meta.epoch;
            }
            Ok(None) => return (seen, None),
            Err(e) => return (seen, Some(e)),
        }
    }
}

#[test]
fn pcap_with_200k_packets_uses_one_small_buffer() {
    let (input, largest) = generated(pcap_header(), pcap_record, PACKETS, 0);
    let mut source = PcapSource::new(input, IoErrors::default()).expect("open");
    assert_eq!(count_all(&mut source), (PACKETS, None));
    assert_eq!(source.buffer_capacity(), INITIAL_BUFFER);
    assert!(largest.load(Ordering::Relaxed) <= INITIAL_BUFFER);
}

#[test]
fn pcapng_with_200k_packets_uses_one_small_buffer() {
    let head = [ng_shb(false), ng_idb(false, 1, 0, None)].concat();
    let (input, largest) = generated(head, ng_record, PACKETS, 0);
    let mut source = PcapngSource::new(input, IoErrors::default()).expect("open");
    assert_eq!(count_all(&mut source), (PACKETS, None));
    assert_eq!(source.buffer_capacity(), INITIAL_BUFFER);
    assert!(largest.load(Ordering::Relaxed) <= INITIAL_BUFFER);
}

#[test]
fn a_huge_declared_pcap_record_stops_growth_at_the_limit() {
    let mut head = pcap_header();
    for v in [1u32, 0, u32::MAX - 16, u32::MAX - 16] {
        head.extend_from_slice(&v.to_le_bytes());
    }
    let (input, largest) = generated(head, pcap_record, 0, 40 * 1024 * 1024);
    let mut source = PcapSource::new(input, IoErrors::default()).expect("open");
    let (seen, err) = count_all(&mut source);
    assert_eq!(seen, 0);
    assert!(matches!(err, Some(ReadError::Truncated(_))));
    assert!(source.buffer_capacity() <= MAX_BLOCK);
    assert!(largest.load(Ordering::Relaxed) <= MAX_BLOCK);
}

#[test]
fn a_huge_declared_pcapng_block_stops_growth_at_the_limit() {
    let mut head = [ng_shb(false), ng_idb(false, 1, 0, None)].concat();
    head.extend_from_slice(&6u32.to_le_bytes());
    head.extend_from_slice(&0x7fff_fff0u32.to_le_bytes());
    let (input, _) = generated(head, ng_record, 0, 40 * 1024 * 1024);
    let mut source = PcapngSource::new(input, IoErrors::default()).expect("open");
    let (seen, err) = count_all(&mut source);
    assert_eq!(seen, 0);
    assert!(matches!(err, Some(ReadError::Truncated(_))));
    assert!(source.buffer_capacity() <= MAX_BLOCK);
}
