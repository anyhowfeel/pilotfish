//! Packet-table column definitions (titles, sizing, comparison).

use std::cmp::Ordering;

use wl_kit::widgets::PROTOCOL_COL_W;
use wl_model::PacketRow;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Col {
    No,
    Time,
    Source,
    Destination,
    Protocol,
    Length,
    Info,
}

pub const ALL: [Col; 7] = [
    Col::No,
    Col::Time,
    Col::Source,
    Col::Destination,
    Col::Protocol,
    Col::Length,
    Col::Info,
];

impl Col {
    /// Stable persistence key.
    pub fn key(self) -> &'static str {
        match self {
            Col::No => "no",
            Col::Time => "time",
            Col::Source => "src",
            Col::Destination => "dst",
            Col::Protocol => "proto",
            Col::Length => "len",
            Col::Info => "info",
        }
    }

    pub fn from_key(key: &str) -> Option<Col> {
        ALL.into_iter().find(|c| c.key() == key)
    }

    pub fn title(self) -> &'static str {
        match self {
            Col::No => "No.",
            Col::Time => "Time",
            Col::Source => "Source",
            Col::Destination => "Destination",
            Col::Protocol => "Protocol",
            Col::Length => "Length",
            Col::Info => "Info",
        }
    }

    /// Numeric columns are right aligned and monospace.
    pub fn numeric(self) -> bool {
        matches!(self, Col::No | Col::Time | Col::Length)
    }

    /// Columns whose header and content are centered (the rest are left/right aligned).
    pub fn centered(self) -> bool {
        self == Col::Protocol
    }

    /// (initial, minimum) width in points; `Info` takes the remainder.
    pub fn widths(self) -> (f32, f32) {
        match self {
            Col::No => (62.0, 44.0),
            Col::Time => (88.0, 60.0),
            Col::Source | Col::Destination => (146.0, 76.0),
            Col::Protocol => (PROTOCOL_COL_W, PROTOCOL_COL_W),
            Col::Length => (62.0, 44.0),
            Col::Info => (240.0, 100.0),
        }
    }

    pub fn compare(self, a: &PacketRow, b: &PacketRow) -> Ordering {
        match self {
            Col::No => a.no.cmp(&b.no),
            Col::Time => a.rel.total_cmp(&b.rel),
            Col::Source => a.src.cmp(&b.src),
            Col::Destination => a.dst.cmp(&b.dst),
            Col::Protocol => a.protocol.cmp(&b.protocol),
            Col::Length => a.len.cmp(&b.len),
            Col::Info => a.info.cmp(&b.info),
        }
    }
}

/// A displayed column: a built-in one or a custom tshark field (`ip.ttl`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ColKey {
    Std(Col),
    Field(String),
}

const FIELD_PREFIX: &str = "f:";

impl ColKey {
    pub fn parse(key: &str) -> Option<ColKey> {
        match key.strip_prefix(FIELD_PREFIX) {
            Some(f) if !f.is_empty() => Some(ColKey::Field(f.to_owned())),
            Some(_) => None,
            None => Col::from_key(key).map(ColKey::Std),
        }
    }

    pub fn key(&self) -> String {
        match self {
            ColKey::Std(c) => c.key().to_owned(),
            ColKey::Field(f) => format!("{FIELD_PREFIX}{f}"),
        }
    }

    pub fn title(&self) -> &str {
        match self {
            ColKey::Std(c) => c.title(),
            ColKey::Field(f) => f,
        }
    }
}
