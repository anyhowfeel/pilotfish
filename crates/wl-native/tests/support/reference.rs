//! tshark's view of a capture, one record per frame.

use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

use wl_model::Transport;

const COLS: [&str; 17] = [
    "frame.number",
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "frame.len",
    "tcp.stream",
    "udp.stream",
    "_ws.col.protocol",
    "ip.proto",
    "ipv6.nxt",
    "_ws.col.info",
];

pub struct Reference {
    fields: Vec<String>,
}

impl Reference {
    pub fn get(&self, name: &str) -> &str {
        let at = COLS.iter().position(|c| *c == name).expect("known column");
        &self.fields[at]
    }

    /// The first non-empty of two columns, like the row parser's `first_of`.
    pub fn either(&self, a: &str, b: &str) -> &str {
        let x = self.get(a);
        if x.is_empty() { self.get(b) } else { x }
    }

    /// The transport the row parser of `wl-tshark` derives from the same columns.
    pub fn transport(&self) -> Transport {
        if !self.either("tcp.srcport", "tcp.dstport").is_empty() {
            return Transport::Tcp;
        }
        if !self.either("udp.srcport", "udp.dstport").is_empty() {
            return Transport::Udp;
        }
        match self.either("ip.proto", "ipv6.nxt").parse::<u8>() {
            Ok(6) => Transport::Tcp,
            Ok(17) => Transport::Udp,
            Ok(1 | 58) => Transport::Icmp,
            _ => Transport::Other,
        }
    }
}

/// Runs tshark over `path`; `None` when it is missing or fails.
pub fn run(path: &Path) -> Option<HashMap<u64, Reference>> {
    let mut cmd = Command::new("tshark");
    cmd.arg("-r").arg(path);
    cmd.args(["-T", "fields", "-E", "separator=/t", "-E", "occurrence=f"]);
    for c in COLS {
        cmd.args(["-e", c]);
    }
    let out = cmd.output().ok().filter(|o| o.status.success())?;
    let mut map = HashMap::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let mut fields: Vec<String> = line.split('\t').map(str::to_owned).collect();
        fields.resize(COLS.len(), String::new());
        if let Ok(no) = fields[0].parse::<u64>() {
            map.insert(no, Reference { fields });
        }
    }
    Some(map)
}

/// Wireshark's stream analysis decorates Info with facts that need other packets: a leading
/// `[TCP ...]` mark and a trailing `(request in N)`, `(reply in N)` or `(no response found!)`.
/// They are a documented limit of the decoder, so they are removed before comparing. Rows of a
/// reassembled HTTP body carry the HTTP line in Info and are skipped (`None`).
pub fn strip_analysis(info: &str) -> Option<String> {
    if info.contains("reassembled in") {
        return None;
    }
    let mut s = info;
    if s.starts_with("[TCP ")
        && let Some(end) = s.find("] ")
    {
        s = &s[end + 2..];
    }
    for marker in [" (request in ", " (reply in ", " (no response found!)"] {
        if let Some(at) = s.find(marker) {
            s = &s[..at];
        }
    }
    Some(s.to_string())
}
