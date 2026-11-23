//! Streaming readers for pcap and pcapng. One packet at a time, so memory stays flat whatever
//! the file size.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use fill::IoErrors;

pub use info::{FileInfo, Format, InterfaceDesc, Stamp};

mod convert;
mod fill;
mod info;
mod pcap;
mod pcapng;
mod stream;

/// Link-layer header type of a packet (`LINKTYPE_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType {
    Ethernet,
    /// BSD loopback / null header.
    Null,
    RawIp,
    LinuxSll,
    LinuxSll2,
    Other(u32),
}

/// What the file says about one packet, apart from its bytes.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PacketMeta {
    /// 1-based, equal to Wireshark's `frame.number`.
    pub no: u64,
    /// Seconds since the Unix epoch.
    pub epoch: f64,
    /// Length on the wire; can exceed the captured length when the snap length cut the packet.
    pub orig_len: u32,
    pub link: LinkType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadError {
    Io(String),
    /// Not a pcap or pcapng file.
    UnknownFormat,
    /// The file ends inside a block, or a block is inconsistent. Packets read before it are valid.
    Truncated(String),
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReadError::Io(e) => write!(f, "{e}"),
            ReadError::UnknownFormat => write!(f, "not a pcap or pcapng file"),
            ReadError::Truncated(e) => write!(f, "capture file is damaged: {e}"),
        }
    }
}

impl std::error::Error for ReadError {}

impl From<ReadError> for wl_model::CaptureError {
    fn from(e: ReadError) -> Self {
        Self::Other(e.to_string())
    }
}

/// A capture file read front to back.
pub trait PacketSource: Send {
    /// Reads the next packet's bytes into `data` (cleared first). `Ok(None)` at the end.
    fn next_packet(&mut self, data: &mut Vec<u8>) -> Result<Option<PacketMeta>, ReadError>;

    /// What the file declares and the totals of the packets read so far.
    fn info(&self) -> &FileInfo;
}

/// Opens `path`, detecting pcap or pcapng from the magic number.
pub fn open(path: &Path) -> Result<Box<dyn PacketSource>, ReadError> {
    let file = File::open(path).map_err(|e| ReadError::Io(format!("{}: {e}", path.display())))?;
    from_reader(file)
}

/// Same as `open` for any byte stream.
pub fn from_reader<R: Read + Send + 'static>(
    mut input: R,
) -> Result<Box<dyn PacketSource>, ReadError> {
    let io = IoErrors::default();
    let mut magic = [0u8; 4];
    let mut got = 0;
    while got < magic.len() {
        match input.read(&mut magic[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(ReadError::Io(e.to_string())),
        }
    }
    if got < magic.len() {
        return Err(ReadError::UnknownFormat);
    }
    let whole = std::io::Cursor::new(magic).chain(input);
    match u32::from_le_bytes(magic) {
        0xa1b2_c3d4 | 0xd4c3_b2a1 | 0xa1b2_3c4d | 0x4d3c_b2a1 => {
            Ok(Box::new(pcap::PcapSource::new(whole, io)?))
        }
        0x0a0d_0d0a => Ok(Box::new(pcapng::PcapngSource::new(whole, io)?)),
        _ => Err(ReadError::UnknownFormat),
    }
}

#[cfg(test)]
#[path = "fixture_tests.rs"]
mod fixture_tests;
#[cfg(test)]
#[path = "fuzz_tests.rs"]
mod fuzz_tests;
#[cfg(test)]
#[path = "info_tests.rs"]
mod info_tests;
#[cfg(test)]
#[path = "memory_tests.rs"]
mod memory_tests;
#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
