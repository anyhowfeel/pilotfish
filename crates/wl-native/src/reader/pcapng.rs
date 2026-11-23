//! pcapng: sections of blocks. Only the section header, interface description and the two packet
//! blocks matter; every other block type is skipped.

use std::io::Read;

use pcap_parser::traits::PcapNGPacketBlock;
use pcap_parser::{Block, OptionCode, PcapBlockOwned, PcapNGReader};

use super::convert::{epoch_from_ticks, link_type, ticks_per_second};
use super::fill::{Fill, IoErrors};
use super::stream::{INITIAL_BUFFER, Step, Stream, map_error};
use super::{
    FileInfo, Format, InterfaceDesc, LinkType, PacketMeta, PacketSource, ReadError, Stamp,
};

pub(super) struct PcapngSource<R: Read> {
    stream: Stream<PcapNGReader<Fill<R>>>,
    state: State,
}

struct Interface {
    link: LinkType,
    snaplen: u32,
    /// Ticks per second; `None` when the file declares a resolution that does not fit a u64.
    per_second: Option<u64>,
}

struct State {
    interfaces: Vec<Interface>,
    /// Simple Packet Blocks carry no timestamp, so they reuse this one.
    last_epoch: f64,
    no: u64,
    info: FileInfo,
    sections: u32,
    /// Index in `info.interfaces` of the current section's first interface.
    base: usize,
}

impl<R: Read> PcapngSource<R> {
    pub fn new(input: R, io: IoErrors) -> Result<Self, ReadError> {
        let fill = Fill::new(input, io.clone());
        let reader = PcapNGReader::new(INITIAL_BUFFER, fill).map_err(|e| map_error(e, &io))?;
        Ok(Self {
            stream: Stream::new(reader, INITIAL_BUFFER, io),
            state: State {
                interfaces: Vec::new(),
                last_epoch: 0.0,
                no: 0,
                info: FileInfo::new(Format::Pcapng),
                sections: 0,
                base: 0,
            },
        })
    }

    #[cfg(test)]
    pub fn buffer_capacity(&self) -> usize {
        self.stream.capacity()
    }
}

impl State {
    fn handle(
        &mut self,
        block: PcapBlockOwned<'_>,
        data: &mut Vec<u8>,
    ) -> Result<Step<PacketMeta>, ReadError> {
        let PcapBlockOwned::NG(block) = block else {
            return Err(ReadError::Truncated("pcap block in a pcapng file".into()));
        };
        match block {
            Block::SectionHeader(shb) => {
                self.interfaces.clear();
                self.base = self.info.interfaces.len();
                if self.sections == 0 {
                    self.read_section_options(&shb);
                }
                self.sections += 1;
                Ok(Step::Skip)
            }
            Block::InterfaceDescription(idb) => {
                self.interfaces.push(Interface {
                    link: link_type(idb.linktype.0),
                    snaplen: idb.snaplen,
                    per_second: ticks_per_second(idb.if_tsresol),
                });
                self.info.interfaces.push(describe(&idb));
                Ok(Step::Skip)
            }
            Block::EnhancedPacket(epb) => {
                let iface = self.interface(epb.if_id)?;
                let per_second = iface.per_second.ok_or_else(|| {
                    ReadError::Truncated("unsupported timestamp resolution".into())
                })?;
                let ticks = (u64::from(epb.ts_high) << 32) | u64::from(epb.ts_low);
                let epoch = epoch_from_ticks(ticks, per_second);
                let link = iface.link;
                data.clear();
                data.extend_from_slice(epb.packet_data());
                let stamp = Stamp::from_ticks(ticks, per_second);
                Ok(self.packet(epb.if_id, Some(stamp), epoch, epb.origlen, link))
            }
            Block::SimplePacket(spb) => {
                let iface = self.interface(0)?;
                let (link, snaplen) = (iface.link, iface.snaplen);
                let mut bytes = spb.packet_data();
                if snaplen > 0 && bytes.len() > snaplen as usize {
                    bytes = &bytes[..snaplen as usize];
                }
                data.clear();
                data.extend_from_slice(bytes);
                Ok(self.packet(0, None, self.last_epoch, spb.origlen, link))
            }
            _ => Ok(Step::Skip),
        }
    }

    fn interface(&self, id: u32) -> Result<&Interface, ReadError> {
        self.interfaces
            .get(id as usize)
            .ok_or_else(|| ReadError::Truncated(format!("packet on unknown interface {id}")))
    }

    fn packet(
        &mut self,
        if_id: u32,
        stamp: Option<Stamp>,
        epoch: f64,
        orig_len: u32,
        link: LinkType,
    ) -> Step<PacketMeta> {
        self.no += 1;
        self.info.record_packet(self.base + if_id as usize, stamp);
        self.last_epoch = epoch;
        Step::Item(PacketMeta {
            no: self.no,
            epoch,
            orig_len,
            link,
        })
    }
}

impl State {
    fn read_section_options(&mut self, shb: &pcap_parser::SectionHeaderBlock<'_>) {
        let text =
            |v: Option<Result<&str, _>>| v.and_then(Result::ok).unwrap_or_default().to_owned();
        self.info.hardware = text(shb.shb_hardware());
        self.info.os = text(shb.shb_os());
        self.info.application = text(shb.shb_userappl());
        self.info.comments = shb
            .options
            .iter()
            .filter(|o| o.code == OptionCode::Comment)
            .filter_map(|o| o.as_str().ok().map(str::to_owned))
            .collect();
    }
}

fn describe(idb: &pcap_parser::InterfaceDescriptionBlock<'_>) -> InterfaceDesc {
    let text = |v: Option<Result<&str, _>>| v.and_then(Result::ok).unwrap_or_default().to_owned();
    let per_second = ticks_per_second(idb.if_tsresol).unwrap_or(0);
    let mut desc = InterfaceDesc::new(link_type(idb.linktype.0), idb.snaplen, per_second);
    desc.name = text(idb.if_name());
    desc.description = text(idb.if_description());
    desc.filter = filter_text(&text(idb.if_filter()));
    desc
}

/// `if_filter` starts with a type byte; only 0 (a filter expression) is text.
fn filter_text(raw: &str) -> String {
    raw.strip_prefix('\0').unwrap_or_default().to_owned()
}

impl<R: Read + Send> PacketSource for PcapngSource<R> {
    fn info(&self) -> &FileInfo {
        &self.state.info
    }

    fn next_packet(&mut self, data: &mut Vec<u8>) -> Result<Option<PacketMeta>, ReadError> {
        let state = &mut self.state;
        self.stream.next(|block| state.handle(block, data))
    }
}

#[cfg(test)]
#[path = "pcapng_tests.rs"]
mod tests;
#[cfg(test)]
#[path = "pcapng_time_tests.rs"]
mod time_tests;
