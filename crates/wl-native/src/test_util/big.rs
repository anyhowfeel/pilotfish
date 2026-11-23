//! A large capture written straight to disk, for memory and throughput measurements.

use std::io::{BufWriter, Write};
use std::net::Ipv4Addr;
use std::path::Path;

use super::{
    ACK, FIN_ACK, Frame, PSH_ACK, PcapStyle, SYN, dns_query_payload, icmp4_echo, pcap_header,
    push_pcap_record, tcp4, udp4,
};

pub const DEFAULT_PACKETS: u64 = 3_000_000;
const CONVERSATIONS: u64 = 50_000;
const HOSTS: u64 = 5_000;
const FLUSH_BYTES: usize = 1 << 20;

/// splitmix64: a good mix of one integer, so a conversation's endpoints follow from its id alone.
fn mix(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

fn host(index: u64) -> Ipv4Addr {
    let i = index as u32;
    Ipv4Addr::new(10, (i >> 8) as u8 & 0x3f, i as u8, 1)
}

fn payload(len: usize, seed: u64) -> Vec<u8> {
    (0..len).map(|i| (seed >> (i % 56)) as u8).collect()
}

/// Packet `n` (0-based) of the synthetic capture: a conversation picked at random, whose
/// protocol depends on its id (60 % TCP, 20 % UDP, 10 % DNS, 10 % ICMP).
fn packet(n: u64, draw: u64) -> Vec<u8> {
    let conv = draw % CONVERSATIONS;
    let id = mix(conv);
    let a = host(id % HOSTS);
    let b = host((id >> 20) % HOSTS);
    let (a_port, b_port) = (
        1024 + (id >> 40) as u16 % 60_000,
        [80, 443, 8080, 22][(id >> 8) as usize % 4],
    );
    let roll = (draw >> 32) % 100;
    let forward = roll.is_multiple_of(2);
    let size = match (draw >> 48) % 10 {
        0..=3 => 0,
        4..=6 => 40 + (draw >> 20) as usize % 200,
        _ => 1_380,
    };
    match conv % 10 {
        0..=5 => {
            let flags = match (roll, size) {
                (0..=2, _) => SYN,
                (97..=99, _) => FIN_ACK,
                (_, 0) => ACK,
                _ => PSH_ACK,
            };
            let (src, dst) = if forward {
                ((a, a_port), (b, b_port))
            } else {
                ((b, b_port), (a, a_port))
            };
            tcp4(
                src,
                dst,
                flags,
                (n as u32).wrapping_mul(1460),
                1,
                &payload(size, draw),
            )
        }
        6 | 7 => {
            let (src, dst) = if forward {
                ((a, a_port), (b, 443))
            } else {
                ((b, 443), (a, a_port))
            };
            udp4(src, dst, &payload(size.max(60), draw))
        }
        8 => {
            let name = format!("h{}.zone{}.example.test", id % 9_973, conv % 97);
            udp4((a, a_port), (b, 53), &dns_query_payload(draw as u16, &name))
        }
        _ => icmp4_echo(a, b, conv as u16, (n % 65_536) as u16),
    }
}

/// Writes `packets` packets to a pcap file one record at a time, so the file never exists in
/// memory. The same `packets` always gives the same bytes; timestamps rise by 1 to 200 us.
pub fn write_big_pcap(path: &Path, packets: u64) {
    let style = PcapStyle::default();
    let mut out = BufWriter::new(std::fs::File::create(path).expect("create capture"));
    out.write_all(&pcap_header(style)).expect("write header");
    let mut buf = Vec::with_capacity(FLUSH_BYTES + 4096);
    let mut micros: u64 = 1_700_000_000_000_000;
    for n in 0..packets {
        let draw = mix(n ^ 0x5eed);
        micros += 1 + (draw >> 8) % 200;
        let frame = Frame::new(micros as f64 / 1e6, packet(n, draw));
        push_pcap_record(&mut buf, style, &frame);
        if buf.len() >= FLUSH_BYTES {
            out.write_all(&buf).expect("write records");
            buf.clear();
        }
    }
    out.write_all(&buf).expect("write records");
    out.flush().expect("flush capture");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NativeBackend;
    use wl_model::CaptureEvent;

    #[test]
    fn same_count_gives_same_bytes_and_every_packet_decodes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (p1, p2) = (dir.path().join("a.pcap"), dir.path().join("b.pcap"));
        write_big_pcap(&p1, 3_000);
        write_big_pcap(&p2, 3_000);
        assert_eq!(
            std::fs::read(&p1).expect("a"),
            std::fs::read(&p2).expect("b")
        );
        let session = NativeBackend::new().start_file(&p1, None).expect("start");
        let (mut rows, mut last) = (0, 0.0);
        for ev in session.events.iter() {
            if let CaptureEvent::Rows(batch) = ev {
                for r in batch {
                    assert!(r.epoch > last && r.src_ip.is_some());
                    last = r.epoch;
                    rows += 1;
                }
            }
        }
        assert_eq!(rows, 3_000);
    }
}
