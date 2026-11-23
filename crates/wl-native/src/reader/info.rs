//! What a capture file says about itself beyond its packets, collected while it is read:
//! format, section options, interface descriptions and the exact first and last timestamps.

use super::LinkType;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Format {
    #[default]
    Pcap,
    PcapNanos,
    Pcapng,
}

/// A packet time without floating point rounding, with the number of decimals its interface
/// resolves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stamp {
    pub secs: u64,
    pub nanos: u32,
    pub digits: u8,
}

impl Stamp {
    pub const ZERO: Self = Self {
        secs: 0,
        nanos: 0,
        digits: 0,
    };

    /// `ticks` at `per_second` ticks per second.
    pub fn from_ticks(ticks: u64, per_second: u64) -> Self {
        let nanos = u128::from(ticks % per_second) * 1_000_000_000 / u128::from(per_second);
        Self {
            secs: ticks / per_second,
            nanos: nanos as u32,
            digits: digits_for(per_second),
        }
    }

    pub fn key(&self) -> (u64, u32) {
        (self.secs, self.nanos)
    }
}

/// Decimals of the first resolution Wireshark names (seconds, deci-, centi-, milli-, micro- or
/// nanoseconds) that is at least as fine as `per_second`.
fn digits_for(per_second: u64) -> u8 {
    match per_second {
        0..=1 => 0,
        2..=10 => 1,
        11..=100 => 2,
        101..=1_000 => 3,
        1_001..=1_000_000 => 6,
        _ => 9,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceDesc {
    pub link: LinkType,
    pub snaplen: u32,
    pub name: String,
    pub description: String,
    pub filter: String,
    pub digits: u8,
    pub packets: u64,
}

impl InterfaceDesc {
    pub fn new(link: LinkType, snaplen: u32, per_second: u64) -> Self {
        Self {
            link,
            snaplen,
            name: String::new(),
            description: String::new(),
            filter: String::new(),
            digits: digits_for(per_second),
            packets: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileInfo {
    pub format: Format,
    /// Options of the first section header (pcapng).
    pub comments: Vec<String>,
    pub application: String,
    pub hardware: String,
    pub os: String,
    pub interfaces: Vec<InterfaceDesc>,
    /// Earliest and latest packet time.
    pub first: Option<Stamp>,
    pub last: Option<Stamp>,
    /// Exact time of the packet read last that carries one.
    pub current: Option<Stamp>,
    /// Whether no packet is older than the one before it.
    pub ordered: bool,
    pub(super) previous: Option<(u64, u32)>,
}

impl FileInfo {
    pub(super) fn new(format: Format) -> Self {
        Self {
            format,
            comments: Vec::new(),
            application: String::new(),
            hardware: String::new(),
            os: String::new(),
            interfaces: Vec::new(),
            first: None,
            last: None,
            current: None,
            ordered: true,
            previous: None,
        }
    }

    /// Counts a packet on interface `index` and folds its time into the extremes.
    pub(super) fn record_packet(&mut self, index: usize, stamp: Option<Stamp>) {
        if let Some(interface) = self.interfaces.get_mut(index) {
            interface.packets += 1;
        }
        let Some(stamp) = stamp else { return };
        self.current = Some(stamp);
        if self.previous.is_some_and(|p| stamp.key() < p) {
            self.ordered = false;
        }
        self.previous = Some(stamp.key());
        if self.first.is_none_or(|f| stamp.key() < f.key()) {
            self.first = Some(stamp);
        }
        if self.last.is_none_or(|l| stamp.key() >= l.key()) {
            self.last = Some(stamp);
        }
    }
}
