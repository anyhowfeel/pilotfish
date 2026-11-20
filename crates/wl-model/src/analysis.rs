//! Pure analysis and feature data types shared across `wl-tshark`, `wl-panels`, and `wl-app`.

use serde::{Deserialize, Serialize};

/// Transport protocol supported by `tshark -z follow`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StreamProtocol {
    Tcp,
    Udp,
}

impl StreamProtocol {
    pub fn as_str(self) -> &'static str {
        match self {
            StreamProtocol::Tcp => "tcp",
            StreamProtocol::Udp => "udp",
        }
    }

    pub fn display_filter(self, stream_id: u32) -> String {
        format!("{}.stream == {stream_id}", self.as_str())
    }
}

/// Output format for `tshark -z follow`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum StreamFormat {
    #[default]
    Ascii,
    Hex,
}

impl StreamFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            StreamFormat::Ascii => "ascii",
            StreamFormat::Hex => "hex",
        }
    }
}

/// One contiguous turn of a client<->server conversation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamTurn {
    /// `true` for Node 0 (client/initiator), `false` for Node 1 (server/responder).
    pub from_client: bool,
    pub text: String,
    pub byte_len: usize,
}

/// Structured output of `tshark -q -z follow,<proto>,<fmt>,<id>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamConversation {
    pub protocol: StreamProtocol,
    pub stream_id: u32,
    pub format: StreamFormat,
    pub client: String,
    pub server: String,
    pub turns: Vec<StreamTurn>,
    pub total_bytes: usize,
}

/// Wireshark Expert Info severity levels (ordered highest -> lowest).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ExpertSeverity {
    Error,
    Warn,
    Note,
    Chat,
}

impl ExpertSeverity {
    pub const ALL: [ExpertSeverity; 4] = [
        ExpertSeverity::Error,
        ExpertSeverity::Warn,
        ExpertSeverity::Note,
        ExpertSeverity::Chat,
    ];

    pub fn label(self) -> &'static str {
        match self {
            ExpertSeverity::Error => "Error",
            ExpertSeverity::Warn => "Warn",
            ExpertSeverity::Note => "Note",
            ExpertSeverity::Chat => "Chat",
        }
    }
}

/// One aggregated row from `tshark -q -z expert`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpertEntry {
    pub severity: ExpertSeverity,
    pub frequency: u64,
    pub group: String,
    pub protocol: String,
    pub summary: String,
}

/// Complete Expert Info report for a capture (or filtered view).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ExpertReport {
    pub entries: Vec<ExpertEntry>,
}

impl ExpertReport {
    pub fn count_by_severity(&self, sev: ExpertSeverity) -> u64 {
        self.entries
            .iter()
            .filter(|e| e.severity == sev)
            .map(|e| e.frequency)
            .sum()
    }

    pub fn total_events(&self) -> u64 {
        self.entries.iter().map(|e| e.frequency).sum()
    }
}

/// One row of `tshark -q -z io,phs` (Protocol Hierarchy Statistics).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProtocolHierarchyNode {
    pub protocol: String,
    pub depth: u16,
    pub frames: u64,
    pub bytes: u64,
    pub frame_pct: f32,
    pub byte_pct: f32,
}

/// Complete Protocol Hierarchy tree flattened in pre-order with `depth`.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct ProtocolHierarchy {
    pub filter: String,
    pub total_frames: u64,
    pub total_bytes: u64,
    pub nodes: Vec<ProtocolHierarchyNode>,
}

/// Severity of a plain-language "Network Health" diagnostic card.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum InsightSeverity {
    Critical,
    Warning,
    Info,
}

/// Plain-language diagnostic card answering "Why is my network slow?".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthInsight {
    pub severity: InsightSeverity,
    pub title: String,
    pub explanation: String,
    pub suggested_filter: Option<String>,
    pub metric: String,
}

/// One display filter field from `tshark -G fields`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilterField {
    pub abbrev: String,
    pub name: String,
    pub field_type: String,
}

/// User bookmark + optional annotation attached to a 1-based frame number.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacketBookmark {
    pub frame_no: u64,
    pub comment: String,
}

/// User-editable packet-list highlight rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColorRule {
    pub name: String,
    /// Protocol name or case-insensitive substring matched against protocol/info.
    pub pattern: String,
    pub color_rgb: [u8; 3],
    pub enabled: bool,
}
