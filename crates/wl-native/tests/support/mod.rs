//! A minimal capture reader for the differential test, independent of `wl_native::reader`.
//! Several test binaries share this module and each uses a part of it.

#![allow(dead_code)]

pub mod compare;
pub mod conn;
pub mod detail_cases;
pub mod edge_cases;
pub mod filter_cases;
pub mod filters;
pub mod fixtures;
pub mod quote_cases;
pub mod reference;
pub mod synthetic;
pub mod verbose;

use std::fs::File;
use std::path::{Path, PathBuf};

use pcap_parser::pcapng::Block;
use pcap_parser::{PcapBlockOwned, PcapError, create_reader};
use wl_native::reader::{LinkType, PacketMeta};
use wl_native::test_util::{PcapStyle, write_pcap};

fn link_type(raw: i32) -> LinkType {
    match raw {
        1 => LinkType::Ethernet,
        0 => LinkType::Null,
        12 | 14 | 101 => LinkType::RawIp,
        113 => LinkType::LinuxSll,
        276 => LinkType::LinuxSll2,
        other => LinkType::Other(u32::try_from(other).unwrap_or(0)),
    }
}

struct Interface {
    link: LinkType,
    resolution: u64,
    offset: u64,
}

pub fn read(path: &Path) -> Vec<(PacketMeta, Vec<u8>)> {
    let mut reader =
        create_reader(1 << 20, File::open(path).expect("open fixture")).expect("reader");
    let (mut out, mut legacy_link, mut nanos) = (Vec::new(), LinkType::Ethernet, false);
    let mut interfaces: Vec<Interface> = Vec::new();
    let mut push = |epoch: f64, orig_len: u32, link: LinkType, data: &[u8]| {
        let no = out.len() as u64 + 1;
        out.push((
            PacketMeta {
                no,
                epoch,
                orig_len,
                link,
            },
            data.to_vec(),
        ));
    };
    loop {
        match reader.next() {
            Ok((offset, block)) => {
                match block {
                    PcapBlockOwned::LegacyHeader(h) => {
                        legacy_link = link_type(h.network.0);
                        nanos = h.is_nanosecond_precision();
                    }
                    PcapBlockOwned::Legacy(b) => {
                        let div = if nanos { 1e9 } else { 1e6 };
                        let epoch = f64::from(b.ts_sec) + f64::from(b.ts_usec) / div;
                        push(epoch, b.origlen, legacy_link, &b.data[..b.caplen as usize]);
                    }
                    PcapBlockOwned::NG(Block::SectionHeader(_)) => interfaces.clear(),
                    PcapBlockOwned::NG(Block::InterfaceDescription(i)) => {
                        interfaces.push(Interface {
                            link: link_type(i.linktype.0),
                            resolution: i.ts_resolution().unwrap_or(1_000_000),
                            offset: u64::try_from(i.ts_offset()).unwrap_or(0),
                        });
                    }
                    PcapBlockOwned::NG(Block::EnhancedPacket(p)) => {
                        let i = &interfaces[p.if_id as usize];
                        let epoch = p.decode_ts_f64(i.offset, i.resolution);
                        push(epoch, p.origlen, i.link, &p.data[..p.caplen as usize]);
                    }
                    _ => {}
                }
                reader.consume(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => reader.refill().expect("refill"),
            Err(e) => panic!("pcap parse error: {e}"),
        }
    }
    out
}

/// Writes cases as pcap files under `dir`; returns their names and paths.
pub fn write_cases(dir: &Path, cases: Vec<synthetic::Case>) -> Vec<(&'static str, PathBuf)> {
    cases
        .into_iter()
        .map(|case| {
            let path = dir.join(format!("{}.pcap", case.name));
            write_pcap(&path, &case.frames, PcapStyle::default());
            (case.name, path)
        })
        .collect()
}
