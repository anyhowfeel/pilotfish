//! Types of the "extras" features: Decode As rules, exported objects and the DNS query log.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// One "Decode As" rule: bind `value` of the dissector table `field` to `protocol`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DecodeAs {
    /// Dissector table, e.g. `tcp.port` or `udp.port`.
    pub field: String,
    pub value: u32,
    /// Short protocol name as used by tshark (`http`, `dns`, ...).
    pub protocol: String,
}

/// One file found in the capture (tshark `--export-objects`).
#[derive(Debug, Clone, PartialEq)]
pub struct ExportObject {
    /// Index in the owning `ObjectSet` (stable until the next extraction).
    pub id: u32,
    /// Name as the protocol carried it (decoded, may contain odd characters; display only).
    pub name: String,
    /// Safe file name to save under (see `sanitize_filename`).
    pub save_name: String,
    pub content_type: String,
    pub size: u64,
    pub host: String,
    /// Frame carrying (the end of) the object, when known.
    pub packet: Option<u64>,
    /// Extracted copy, always inside `ObjectSet::dir`.
    pub path: PathBuf,
}

/// All objects of one protocol, extracted into `dir` (owned by the backend).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ObjectSet {
    pub protocol: String,
    pub dir: PathBuf,
    pub objects: Vec<ExportObject>,
    /// Extraction stopped at the size cap: the list is incomplete.
    pub truncated: bool,
}

/// DNS response code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rcode {
    NoError,
    FormErr,
    ServFail,
    NxDomain,
    NotImp,
    Refused,
    Other(u8),
}

impl Rcode {
    pub fn from_code(c: u8) -> Rcode {
        match c {
            0 => Rcode::NoError,
            1 => Rcode::FormErr,
            2 => Rcode::ServFail,
            3 => Rcode::NxDomain,
            4 => Rcode::NotImp,
            5 => Rcode::Refused,
            n => Rcode::Other(n),
        }
    }

    pub fn label(self) -> String {
        match self {
            Rcode::NoError => "NOERROR".into(),
            Rcode::FormErr => "FORMERR".into(),
            Rcode::ServFail => "SERVFAIL".into(),
            Rcode::NxDomain => "NXDOMAIN".into(),
            Rcode::NotImp => "NOTIMP".into(),
            Rcode::Refused => "REFUSED".into(),
            Rcode::Other(n) => format!("RCODE{n}"),
        }
    }
}

/// One DNS transaction: a query and, when seen, its response.
#[derive(Debug, Clone, PartialEq)]
pub struct DnsQuery {
    /// Query frame (the one "Show in Packets" jumps to).
    pub frame: u64,
    pub response_frame: Option<u64>,
    /// Seconds since the first packet of the capture, at the query.
    pub rel: f64,
    pub client: String,
    pub server: String,
    pub name: String,
    /// "A", "AAAA", "HTTPS", or the numeric type when unknown.
    pub qtype: String,
    /// None = no response seen.
    pub rcode: Option<Rcode>,
    pub answers: Vec<String>,
    /// Query -> response latency (`dns.time`) in milliseconds.
    pub rtt_ms: Option<f64>,
    pub retransmission: bool,
}

const MAX_NAME: usize = 120;

/// Turns an untrusted file name into one that is safe to create inside a chosen directory:
/// no path separators, no parent references, no leading dots, no control or reserved characters.
pub fn sanitize_filename(raw: &str) -> String {
    let mapped: String = raw
        .chars()
        .map(|c| match c {
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            c if c.is_control() => '_',
            c => c,
        })
        .collect();
    let trimmed = mapped.trim_matches(|c: char| c == '.' || c.is_whitespace());
    let kept: String = trimmed.chars().take(MAX_NAME).collect();
    if kept.chars().all(|c| c == '_') {
        "object".to_owned()
    } else {
        kept
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_path_traversal() {
        for evil in [
            "../../etc/passwd",
            "..\\..\\windows\\system32",
            "/etc/shadow",
            "..",
            ".",
            "a/../../b",
            "",
            "   ",
            "\0",
        ] {
            let s = sanitize_filename(evil);
            assert!(!s.contains('/') && !s.contains('\\'), "{evil:?} -> {s:?}");
            assert!(!s.starts_with('.') && s != "..", "{evil:?} -> {s:?}");
            assert!(!s.is_empty());
        }
        assert_eq!(sanitize_filename("../../etc/passwd"), "_.._etc_passwd");
        assert_eq!(sanitize_filename("/"), "object");
    }

    #[test]
    fn keeps_normal_names_and_limits_length() {
        assert_eq!(sanitize_filename("logo.png"), "logo.png");
        assert_eq!(sanitize_filename("a b.txt"), "a b.txt");
        assert_eq!(sanitize_filename("x\u{7}y\nz"), "x_y_z");
        assert!(sanitize_filename(&"a".repeat(500)).chars().count() <= MAX_NAME);
    }

    #[test]
    fn rcode_labels() {
        assert_eq!(Rcode::from_code(3).label(), "NXDOMAIN");
        assert_eq!(Rcode::from_code(9).label(), "RCODE9");
    }
}
