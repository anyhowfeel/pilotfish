//! Legacy pcap: one global header, then a record header and the bytes of each packet.

use std::io::Read;

use pcap_parser::{LegacyPcapReader, PcapBlockOwned};

use super::convert::{epoch, link_type};
use super::fill::{Fill, IoErrors};
use super::stream::{INITIAL_BUFFER, Step, Stream, map_error};
use super::{
    FileInfo, Format, InterfaceDesc, LinkType, PacketMeta, PacketSource, ReadError, Stamp,
};

pub(super) struct PcapSource<R: Read> {
    stream: Stream<LegacyPcapReader<Fill<R>>>,
    state: State,
}

struct State {
    link: LinkType,
    per_second: u64,
    no: u64,
    info: FileInfo,
}

impl<R: Read> PcapSource<R> {
    pub fn new(input: R, io: IoErrors) -> Result<Self, ReadError> {
        let fill = Fill::new(input, io.clone());
        let reader = LegacyPcapReader::new(INITIAL_BUFFER, fill).map_err(|e| map_error(e, &io))?;
        Ok(Self {
            stream: Stream::new(reader, INITIAL_BUFFER, io),
            state: State {
                link: LinkType::Other(0),
                per_second: 1_000_000,
                no: 0,
                info: FileInfo::new(Format::Pcap),
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
        match block {
            PcapBlockOwned::LegacyHeader(header) => {
                self.link = link_type(header.network.0);
                let nanos = header.is_nanosecond_precision();
                self.per_second = if nanos { 1_000_000_000 } else { 1_000_000 };
                self.info.format = if nanos {
                    Format::PcapNanos
                } else {
                    Format::Pcap
                };
                self.info.interfaces = vec![InterfaceDesc::new(
                    self.link,
                    header.snaplen,
                    self.per_second,
                )];
                Ok(Step::Skip)
            }
            PcapBlockOwned::Legacy(record) => {
                data.clear();
                data.extend_from_slice(record.data);
                self.no += 1;
                let fraction = u64::from(record.ts_usec);
                let ticks = u64::from(record.ts_sec) * self.per_second + fraction;
                self.info
                    .record_packet(0, Some(Stamp::from_ticks(ticks, self.per_second)));
                Ok(Step::Item(PacketMeta {
                    no: self.no,
                    epoch: epoch(u64::from(record.ts_sec), fraction, self.per_second),
                    orig_len: record.origlen,
                    link: self.link,
                }))
            }
            PcapBlockOwned::NG(_) => {
                Err(ReadError::Truncated("pcapng block in a pcap file".into()))
            }
        }
    }
}

impl<R: Read + Send> PacketSource for PcapSource<R> {
    fn info(&self) -> &FileInfo {
        &self.state.info
    }

    fn next_packet(&mut self, data: &mut Vec<u8>) -> Result<Option<PacketMeta>, ReadError> {
        let state = &mut self.state;
        self.stream.next(|block| state.handle(block, data))
    }
}

#[cfg(test)]
#[path = "pcap_tests.rs"]
mod tests;
